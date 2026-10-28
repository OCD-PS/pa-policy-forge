(() => {
  "use strict";

  const script = document.currentScript;
  if (!script || document.querySelector("[data-bug-report-launcher]")) return;

  const styles = document.createElement("style");
  styles.textContent = `
    .bug-report-launcher{position:fixed;z-index:10000;left:16px;bottom:16px;width:48px;height:48px;border:0;border-radius:50%;background:#ff7900;color:#111;font-size:24px;font-weight:900;box-shadow:0 5px 20px #0009;cursor:pointer}
    .bug-report-launcher:hover,.bug-report-launcher:focus{background:#ff9833;outline:3px solid #fff}
    .bug-report-dialog{width:min(680px,calc(100vw - 24px));max-height:calc(100vh - 24px);padding:0;border:1px solid #555;border-radius:10px;background:#161616;color:#eee;box-shadow:0 24px 70px #000b}
    .bug-report-dialog::backdrop{background:#000b;backdrop-filter:blur(2px)}.bug-report-dialog form{padding:20px}
    .bug-report-dialog .stack{display:grid;gap:14px}.bug-report-dialog .field{display:grid;gap:6px}.bug-report-dialog label{font-weight:700}
    .bug-report-dialog input,.bug-report-dialog textarea{box-sizing:border-box;width:100%;border:1px solid #484848;border-radius:5px;padding:10px;background:#090909;color:#fff;font:inherit}
    .bug-report-preview{display:block;max-width:100%;max-height:35vh;object-fit:contain;border:1px solid #444;border-radius:6px;background:#080808}
    .bug-report-actions{display:flex;justify-content:flex-end;gap:8px}.bug-report-status{min-height:1.4em}.bug-report-close{margin-left:auto}
    .bug-report-dialog button{min-height:38px;border:1px solid #555;border-radius:5px;padding:8px 13px;background:#292929;color:#fff;font-weight:700;cursor:pointer}
    .bug-report-dialog button[type=submit]{border-color:#ff7900;background:#ff7900;color:#111}.bug-report-dialog button:disabled{opacity:.55;cursor:wait}
  `;
  document.head.append(styles);

  const launcher = document.createElement("button");
  launcher.type = "button";
  launcher.className = "bug-report-launcher";
  launcher.dataset.bugReportLauncher = "";
  launcher.setAttribute("aria-label", "Bug melden");
  launcher.title = "Bug melden";
  launcher.textContent = "!";

  const dialog = document.createElement("dialog");
  dialog.className = "bug-report-dialog";
  dialog.setAttribute("aria-labelledby", "bug-report-title");
  dialog.innerHTML = `
    <form method="dialog" class="stack" data-bug-report-form>
      <div class="card-header"><div><h2 id="bug-report-title">Bug melden</h2><p>Controleer de screenshot voor je de melding verstuurt.</p></div><button type="button" class="bug-report-close" data-close>Sluiten</button></div>
      <div data-preview-wrap><p class="bug-report-status" data-capture-status>Screenshot wordt gemaakt…</p><img class="bug-report-preview" data-preview alt="Voorbeeld van de screenshot"></div>
      <div class="field"><label for="bug-report-email">Je e-mailadres</label><input id="bug-report-email" name="email" type="email" maxlength="254" autocomplete="email" required></div>
      <div class="field"><label for="bug-report-description">Wat ging er mis?</label><textarea id="bug-report-description" name="description" rows="5" maxlength="5000" required></textarea></div>
      <p class="bug-report-status" data-result role="status" aria-live="polite"></p>
      <div class="bug-report-actions"><button type="submit" data-submit disabled>Melding versturen</button></div>
    </form>`;
  document.body.append(launcher, dialog);

  let screenshotBlob = null;
  let previewUrl = "";
  const status = dialog.querySelector("[data-capture-status]");
  const result = dialog.querySelector("[data-result]");
  const submit = dialog.querySelector("[data-submit]");
  const form = dialog.querySelector("[data-bug-report-form]");

  function openBugReport(event) {
    const clickedLauncher = event?.currentTarget || launcher;
    const owningModal = clickedLauncher.closest("dialog[open]");
    const dialogHost = owningModal || document.body;
    if (dialog.parentElement !== dialogHost) dialogHost.append(dialog);
    screenshotBlob = null;
    result.textContent = "";
    submit.disabled = true;
    status.textContent = "Screenshot wordt gemaakt…";
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    previewUrl = "";
    dialog.showModal();
    try {
      captureViewport().then((blob) => {
        if (!blob || blob.size > 2 * 1024 * 1024) throw new Error("too-large");
        screenshotBlob = blob;
        previewUrl = URL.createObjectURL(blob);
        dialog.querySelector("[data-preview]").src = previewUrl;
        status.textContent = "Screenshot klaar. Bekende geheime formuliervelden zijn afgeschermd. Andere gevoelige tekst kan zichtbaar zijn; controleer de afbeelding voor verzending.";
        submit.disabled = false;
      }).catch(() => {
        status.textContent = "De screenshot kon niet veilig worden gemaakt. Vernieuw de pagina en probeer opnieuw.";
      });
    } catch {
      status.textContent = "De screenshot kon niet veilig worden gemaakt. Vernieuw de pagina en probeer opnieuw.";
    }
  }

  launcher.addEventListener("click", openBugReport);

  function syncModalLaunchers() {
    const openDialogs = new Set(
      Array.from(document.querySelectorAll("dialog[open]"))
        .filter((openDialog) => openDialog !== dialog)
    );
    document.querySelectorAll("[data-bug-report-modal-launcher]").forEach((button) => {
      if (!openDialogs.has(button.closest("dialog"))) button.remove();
    });
    openDialogs.forEach((openDialog) => {
      if (openDialog.querySelector("[data-bug-report-modal-launcher]")) return;
      const modalLauncher = launcher.cloneNode(true);
      modalLauncher.dataset.bugReportModalLauncher = "";
      modalLauncher.addEventListener("click", openBugReport);
      openDialog.append(modalLauncher);
    });
  }

  // Native modal dialogs enter the browser top layer and make the rest of the
  // document inert, so z-index alone cannot keep the body launcher clickable.
  const modalObserver = new MutationObserver((records) => {
    if (records.some((record) => record.target?.tagName === "DIALOG")) {
      syncModalLaunchers();
    }
  });
  modalObserver.observe(document.body, {
    attributes: true,
    attributeFilter: ["open"],
    subtree: true,
  });
  syncModalLaunchers();

  function safePageClone() {
    const clonedRoot = document.documentElement.cloneNode(true);
    clonedRoot.querySelectorAll("[data-bug-report-launcher],.bug-report-dialog,script,iframe,object,embed,link[rel~='stylesheet']").forEach((node) => node.remove());
    clonedRoot.querySelectorAll("input,textarea,select").forEach((field) => {
      const key = `${field.name || ""} ${field.id || ""} ${field.autocomplete || ""}`.toLowerCase();
      if (field.type === "password" || /password|secret|token|api.?key|credential|private.?key/.test(key)) {
        field.value = "[verborgen]";
        field.setAttribute("value", "[verborgen]");
        if (field.tagName === "TEXTAREA") field.textContent = "[verborgen]";
      } else if (field.tagName === "INPUT" && field.type !== "hidden") {
        if (["checkbox", "radio"].includes(field.type)) field.toggleAttribute("checked", field.checked);
        else field.setAttribute("value", field.value);
      } else if (field.tagName === "TEXTAREA") {
        field.textContent = field.value;
      } else if (field.tagName === "SELECT") {
        field.querySelectorAll("option").forEach((option) => option.toggleAttribute("selected", option.selected));
      }
      if (field.type === "hidden") field.remove();
    });
    clonedRoot.querySelectorAll("img").forEach((image) => {
      try {
        if (new URL(image.src, location.href).origin !== location.origin) image.remove();
      } catch { image.remove(); }
    });
    const rootStyle = getComputedStyle(document.documentElement);
    clonedRoot.style.cssText += `;position:absolute;left:${-window.scrollX}px;top:${-window.scrollY}px;width:${document.documentElement.clientWidth}px;min-height:${document.documentElement.scrollHeight}px;margin:0;color:${rootStyle.color};background:${rootStyle.backgroundColor};font:${rootStyle.font};overflow:visible`;
    const head = clonedRoot.querySelector("head");
    const styleNode = document.createElementNS("http://www.w3.org/1999/xhtml", "style");
    styleNode.textContent = collectStyles();
    head.prepend(styleNode);
    return clonedRoot;
  }

  function collectStyles() {
    let css = "";
    for (const sheet of document.styleSheets) {
      try {
        for (const rule of sheet.cssRules) css += `${rule.cssText}\n`;
      } catch { /* Cross-origin styles cannot be copied into the local snapshot. */ }
    }
    return css.replace(/@import[^;]+;/gi, "");
  }

  async function captureViewport() {
    const width = Math.max(1, Math.min(window.innerWidth, 2400));
    const height = Math.max(1, Math.min(window.innerHeight, 1600));
    const scale = Math.min(1, 2400 / width, 1600 / height);
    const root = safePageClone();
    const container = document.createElementNS("http://www.w3.org/1999/xhtml", "div");
    container.setAttribute("style", `position:relative;width:${width}px;height:${height}px;overflow:hidden`);
    container.append(root);
    const xhtml = new XMLSerializer().serializeToString(container);
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${Math.round(width * scale)}" height="${Math.round(height * scale)}" viewBox="0 0 ${width} ${height}"><foreignObject width="100%" height="100%">${xhtml}</foreignObject></svg>`;
    const url = URL.createObjectURL(new Blob([svg], { type: "image/svg+xml;charset=utf-8" }));
    try {
      const image = new Image();
      image.src = url;
      await image.decode();
      const canvas = document.createElement("canvas");
      canvas.width = Math.round(width * scale);
      canvas.height = Math.round(height * scale);
      const context = canvas.getContext("2d", { alpha: false });
      context.drawImage(image, 0, 0, canvas.width, canvas.height);
      return await new Promise((resolve) => canvas.toBlob((blob) => resolve(blob), "image/png"));
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  dialog.querySelector("[data-close]").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    previewUrl = "";
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!screenshotBlob || !form.reportValidity()) return;
    submit.disabled = true;
    result.textContent = "Melding wordt verstuurd…";
    const data = new FormData(form);
    data.set("csrf", script.dataset.csrf || "");
    data.set("page_path", location.pathname);
    data.set("screenshot", screenshotBlob, "bug-report.png");
    try {
      const response = await fetch("/bug-reports", { method: "POST", body: data, credentials: "same-origin" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Melding kon niet worden opgeslagen.");
      result.textContent = `Bedankt. Je melding #${payload.id} staat veilig in de reviewwachtrij.`;
      form.querySelector("textarea").value = "";
      form.querySelector("[name=email]").value = "";
      screenshotBlob = null;
      submit.textContent = "Gemeld";
    } catch (error) {
      result.textContent = error.message || "Verzenden mislukt. Probeer opnieuw.";
      submit.disabled = false;
    }
  });
})();
