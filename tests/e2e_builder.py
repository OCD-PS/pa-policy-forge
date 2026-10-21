#!/usr/bin/env python3
import ipaddress, json, os, pathlib, shutil, ssl, subprocess, sys, tempfile, threading
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from flask import Flask, Response, request
from werkzeug.serving import make_server

tmp=tempfile.TemporaryDirectory(prefix="ppf-e2e-")
os.environ["PPF_DATA_DIR"]=tmp.name
os.environ["PPF_BOOTSTRAP_PASSWORD"]="e2e-test-bootstrap-password"
os.environ["PPF_SYSLOG_PORT"]="15515"
from app import main as forge
from vendor.paloalto_light_syslog import parse_panos_syslog

fake_panos=Flask("fake-panos")
@fake_panos.route("/api", methods=["GET", "POST"])
@fake_panos.route("/api/", methods=["GET", "POST"])
def fake_api():
    if request.values.get("type") == "keygen":
        return Response("<response status='success'><result><key>e2e-key</key></result></response>", mimetype="application/xml")
    xpath = request.values.get("xpath", "")
    if request.values.get("type") == "config" and request.values.get("action") == "get" and xpath.endswith("/rulebase/security/rules"):
        rules = """<entry name="allow-web-out"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>allow</action><disabled>yes</disabled></entry>"""
        return Response(f"<response status='success'><result>{rules}</result></response>", mimetype="application/xml")
    return Response("<response status='success'><result><config/></result></response>", mimetype="application/xml")

tls_dir=pathlib.Path(tmp.name)/"tls"; tls_dir.mkdir()
tls_ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
tls_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
tls_issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Policy Forge E2E CA")])
tls_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"127.0.0.1")])
tls_now=datetime.now(timezone.utc)
tls_ca_cert=(x509.CertificateBuilder().subject_name(tls_issuer).issuer_name(tls_issuer)
    .public_key(tls_ca_key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(tls_now-timedelta(minutes=1)).not_valid_after(tls_now+timedelta(days=30))
    .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
    .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,
        data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,
        encipher_only=None,decipher_only=None),critical=True)
    .sign(tls_ca_key,hashes.SHA256()))
tls_cert=(x509.CertificateBuilder().subject_name(tls_name).issuer_name(tls_issuer)
    .public_key(tls_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(tls_now-timedelta(minutes=1)).not_valid_after(tls_now+timedelta(days=1))
    .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),critical=False)
    .sign(tls_ca_key,hashes.SHA256()))
tls_ca=tls_dir/"ca.pem"; tls_ca.write_bytes(tls_ca_cert.public_bytes(serialization.Encoding.PEM))
tls_cert_file=tls_dir/"server.pem"; tls_cert_file.write_bytes(tls_cert.public_bytes(serialization.Encoding.PEM))
tls_key_file=tls_dir/"server.key"; tls_key_file.write_bytes(tls_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
os.environ["PPF_PANOS_CA_BUNDLE"]=str(tls_ca)
tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls_context.load_cert_chain(str(tls_cert_file),str(tls_key_file))
fake_server=make_server("127.0.0.1",0,fake_panos,ssl_context=tls_context)
threading.Thread(target=fake_server.serve_forever,daemon=True).start()

sample=(pathlib.Path(__file__).with_name("panos-traffic-allow.syslog")).read_text()
flow=parse_panos_syslog(sample)
assert flow is not None
forge.flow_store.add_flow(flow)
settings={"zones":{"trust":"client","untrust":"internet"},"min_sessions":1,"disabled":True,"tags":["PA Policy Forge QA"],"global_ping":True,"global_dns":True,"endpoint":f"https://127.0.0.1:{fake_server.server_port}","vsys":"vsys1","device_group":"","rulebase":"pre","folder":"","object_folder":"","log_profile":"","profile_group":""}
with forge.db() as conn:
    cur=conn.execute("INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",("E2E",1,flow.serial,"","panos",json.dumps(settings),b"",forge.now(),forge.now()))
    profile=conn.execute("SELECT * FROM profiles WHERE id=?",(cur.lastrowid,)).fetchone()
run=pathlib.Path(tmp.name)/"run"; run.mkdir()
assert forge.export_profile_flows(profile,run/"flows.csv")==1
forge.write_config(profile,run,False)
for name in ("bdnd_panos_policy_builder.py","bdnd_bpa_policy_builder.py","panos_tls.py"):
    shutil.copy(forge.BASE/"vendor"/name,run/name)
result=subprocess.run([sys.executable,"bdnd_panos_policy_builder.py"],cwd=run,capture_output=True,text=True,timeout=120)
assert result.returncode==0,result.stdout+result.stderr
assert (run/"policy.xml").exists() and (run/"review.csv").exists()
assert "<profile-setting>" not in (run/"policy.xml").read_text()
fake_server.shutdown()
print("e2e_builder_ok")
