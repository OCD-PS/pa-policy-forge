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
      <div data-preview-wrap><p class="bug-report-status" data-capture-status role="status" aria-live="polite">Screenshot wordt gemaakt…</p><img class="bug-report-preview" data-preview alt="Voorbeeld van de screenshot"><button type="button" data-capture-retry hidden>Screenshot opnieuw maken</button><label data-capture-fallback hidden>Automatische opname lukt niet? Voeg een PNG-screenshot toe en controleer die op gevoelige informatie.<input type="file" accept="image/png" data-capture-file></label></div>
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
  const captureRetry = dialog.querySelector("[data-capture-retry]");
  const captureFallback = dialog.querySelector("[data-capture-fallback]");
  const captureFile = dialog.querySelector("[data-capture-file]");
  const form = dialog.querySelector("[data-bug-report-form]");

  function openBugReport(event) {
    const clickedLauncher = event?.currentTarget || launcher;
    const owningModal = clickedLauncher.closest("dialog[open]");
    const dialogHost = owningModal || document.body;
    if (dialog.parentElement !== dialogHost) dialogHost.append(dialog);
    screenshotBlob = null;
    captureFile.value = "";
    captureFallback.hidden = true;
    result.textContent = "";
    submit.disabled = true;
    status.textContent = "Screenshot wordt gemaakt…";
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    previewUrl = "";
    dialog.showModal();
    captureScreenshot();
  }

  async function captureScreenshot() {
    captureRetry.hidden = true;
    screenshotBlob = null;
    submit.disabled = true;
    status.textContent = "Screenshot wordt gemaakt…";
    try {
      const blob = await captureViewport();
      screenshotBlob = blob;
      previewUrl = URL.createObjectURL(blob);
      dialog.querySelector("[data-preview]").src = previewUrl;
      status.textContent = "Screenshot klaar. Bekende geheime formuliervelden zijn afgeschermd. Andere gevoelige tekst kan zichtbaar zijn; controleer de afbeelding voor verzending.";
      submit.disabled = false;
    } catch (error) {
      status.textContent = error?.captureStage === "too-large"
        ? "De screenshot blijft te groot. Verklein het browservenster en probeer opnieuw."
        : formatCaptureError(error);
      captureRetry.hidden = false;
      captureFallback.hidden = false;
    }
  }

  function formatCaptureError(error) {
    const stageLabels = {
      "page-copy": "de pagina kopiëren",
      "svg-serialize": "de kopie voorbereiden",
      "svg-decode": "de afbeelding in de browser laden",
      "canvas-create": "de afbeelding voorbereiden",
      "canvas-render": "de pagina tekenen",
      "png-export": "de PNG maken",
    };
    const safeErrorNames = new Set([
      "EncodingError", "InvalidStateError", "NotSupportedError", "OperationError", "SecurityError",
    ]);
    const code = safeErrorNames.has(error?.cause?.name) ? error.cause.name : "browserfout";
    const stage = stageLabels[error?.captureStage] || "de pagina vastleggen";
    return `Automatische screenshot faalde bij ${stage} (${code}). Probeer opnieuw of voeg een PNG toe; je melding blijft staan.`;
  }

  function captureFailure(stage, cause) {
    const error = new Error(stage);
    error.captureStage = stage;
    error.cause = cause;
    return error;
  }

  launcher.addEventListener("click", openBugReport);
  captureRetry.addEventListener("click", captureScreenshot);
  captureFile.addEventListener("change", () => {
    const file = captureFile.files?.[0];
    if (!file) return;
    if (file.type !== "image/png" || file.size > 2 * 1024 * 1024) {
      screenshotBlob = null;
      submit.disabled = true;
      status.textContent = "Kies een PNG-bestand van maximaal 2 MB.";
      return;
    }
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    screenshotBlob = file;
    previewUrl = URL.createObjectURL(file);
    dialog.querySelector("[data-preview]").src = previewUrl;
    status.textContent = "Screenshot toegevoegd. Controleer de afbeelding op wachtwoorden en andere gevoelige informatie.";
    submit.disabled = false;
  });

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
    clonedRoot.querySelectorAll("[data-bug-report-modal-launcher]").forEach((node) => node.remove());
    const sourceDialogs = Array.from(document.querySelectorAll("dialog:not(.bug-report-dialog)"));
    clonedRoot.querySelectorAll("dialog:not(.bug-report-dialog)").forEach((clonedDialog, index) => {
      const sourceDialog = sourceDialogs[index];
      if (!sourceDialog?.open) {
        clonedDialog.remove();
        return;
      }
      // Render the active app modal as ordinary markup in the SVG snapshot.
      // Modal top-layer state is browser-managed and does not serialize reliably.
      const snapshotDialog = document.createElement("div");
      Array.from(clonedDialog.attributes).forEach((attribute) => {
        if (attribute.name !== "open") snapshotDialog.setAttribute(attribute.name, attribute.value);
      });
      const sourceStyle = getComputedStyle(sourceDialog);
      for (const property of sourceStyle) {
        snapshotDialog.style.setProperty(property, sourceStyle.getPropertyValue(property));
      }
      snapshotDialog.style.setProperty("display", "block");
      while (clonedDialog.firstChild) snapshotDialog.append(clonedDialog.firstChild);
      clonedDialog.replaceWith(snapshotDialog);
    });
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
    const initialScale = Math.min(1, 1600 / width, 1000 / height);
    let root;
    try {
      root = safePageClone();
    } catch (error) {
      throw captureFailure("page-copy", error);
    }
    let xhtml;
    try {
      const container = document.createElementNS("http://www.w3.org/1999/xhtml", "div");
      container.setAttribute("style", `position:relative;width:${width}px;height:${height}px;overflow:hidden`);
      container.append(root);
      xhtml = new XMLSerializer().serializeToString(container);
    } catch (error) {
      throw captureFailure("svg-serialize", error);
    }

    for (const scale of [initialScale, initialScale * 0.8, initialScale * 0.65, initialScale * 0.5]) {
      const outputWidth = Math.max(1, Math.round(width * scale));
      const outputHeight = Math.max(1, Math.round(height * scale));
      let imageSource;
      try {
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${outputWidth}" height="${outputHeight}" viewBox="0 0 ${width} ${height}"><foreignObject width="100%" height="100%">${xhtml}</foreignObject></svg>`;
        // Chromium taints canvas exports from blob-backed SVGs containing
        // foreignObject. A data URL keeps this local snapshot origin-clean.
        imageSource = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
      } catch (error) {
        throw captureFailure("svg-serialize", error);
      }
      const image = new Image();
      image.src = imageSource;
      try {
        await image.decode();
      } catch (error) {
        throw captureFailure("svg-decode", error);
      }
      const canvas = document.createElement("canvas");
      canvas.width = outputWidth;
      canvas.height = outputHeight;
      const context = canvas.getContext("2d", { alpha: false });
      if (!context) throw captureFailure("canvas-create", new Error("unavailable"));
      try {
        context.drawImage(image, 0, 0, canvas.width, canvas.height);
      } catch (error) {
        throw captureFailure("canvas-render", error);
      }
      let blob;
      try {
        blob = await new Promise((resolve) => canvas.toBlob((value) => resolve(value), "image/png"));
      } catch (error) {
        throw captureFailure("png-export", error);
      }
      if (!blob) throw captureFailure("png-export", new Error("empty result"));
      if (blob.size <= 2 * 1024 * 1024) return blob;
    }
    throw captureFailure("too-large", null);
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
