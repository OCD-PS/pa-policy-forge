#!/usr/bin/env python3
import json, os, pathlib, shutil, subprocess, tempfile, threading

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
    return Response("<response status='success'><result><config/></result></response>", mimetype="application/xml")

fake_server=make_server("127.0.0.1",0,fake_panos,ssl_context="adhoc")
threading.Thread(target=fake_server.serve_forever,daemon=True).start()

sample=(pathlib.Path(__file__).with_name("panos-traffic-allow.syslog")).read_text()
flow=parse_panos_syslog(sample)
assert flow is not None
forge.flow_store.add_flow(flow)
settings={"zones":{"trust":"client","untrust":"internet"},"min_sessions":1,"disabled":True,"tags":["PA Policy Forge QA"],"global_ping":True,"global_dns":True,"endpoint":f"https://127.0.0.1:{fake_server.server_port}","vsys":"vsys1","device_group":"","rulebase":"pre","folder":"","object_folder":"","log_profile":""}
with forge.db() as conn:
    cur=conn.execute("INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",("E2E",1,flow.serial,"","panos",json.dumps(settings),b"",forge.now(),forge.now()))
    profile=conn.execute("SELECT * FROM profiles WHERE id=?",(cur.lastrowid,)).fetchone()
run=pathlib.Path(tmp.name)/"run"; run.mkdir()
assert forge.export_profile_flows(profile,run/"flows.csv")==1
forge.write_config(profile,run,False)
for name in ("bdnd_panos_policy_builder.py","bdnd_bpa_policy_builder.py"):
    shutil.copy(forge.BASE/"vendor"/name,run/name)
result=subprocess.run(["python3","bdnd_panos_policy_builder.py"],cwd=run,capture_output=True,text=True,timeout=120)
assert result.returncode==0,result.stdout+result.stderr
assert (run/"policy.xml").exists() and (run/"review.csv").exists()
fake_server.shutdown()
print("e2e_builder_ok")
