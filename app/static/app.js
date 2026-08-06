(function () {
  "use strict";

  function all(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function activateSection(id, updateHash) {
    if (!id) return;
    var section = document.getElementById(id);
    if (!section || !section.classList.contains("page-section")) return;

    all(".page-section").forEach(function (item) {
      item.hidden = item !== section;
      item.classList.toggle("active", item === section);
    });
    all("[data-section]").forEach(function (link) {
      var active = link.getAttribute("data-section") === id;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });

    var title = section.getAttribute("data-title");
    var titleNode = document.querySelector("[data-page-title]");
    if (title && titleNode) titleNode.textContent = title;
    if (updateHash && history.replaceState) history.replaceState(null, "", "#" + id);
    document.body.classList.remove("nav-open");
  }

  function setupNavigation() {
    all("[data-section]").forEach(function (link) {
      link.addEventListener("click", function (event) {
        var id = link.getAttribute("data-section");
        if (document.getElementById(id)) {
          event.preventDefault();
          activateSection(id, true);
        }
      });
    });
    var hash = window.location.hash.replace(/^#/, "");
    var preferred = hash || (document.querySelector("[data-section].active") || {}).dataset?.section;
    if (preferred) activateSection(preferred, false);

  }

  function setupPasswords() {
    all("[data-password-toggle]").forEach(function (button) {
      var explicitId = button.getAttribute("data-password-toggle");
      var input = explicitId ? document.getElementById(explicitId) : button.closest(".input-wrap")?.querySelector("input");
      if (!input) return;
      button.addEventListener("click", function () {
        var showing = input.type === "text";
        input.type = showing ? "password" : "text";
        button.setAttribute("aria-pressed", String(!showing));
        button.setAttribute("aria-label", showing ? "Wachtwoord tonen" : "Wachtwoord verbergen");
        button.textContent = showing ? "Toon" : "Verberg";
      });
    });
  }

  function setupConfirmations() {
    document.addEventListener("click", function (event) {
      var target = event.target.closest("[data-confirm]");
      if (!target) return;
      var message = target.getAttribute("data-confirm") || "Weet je zeker dat je wilt doorgaan?";
      if (!window.confirm(message)) event.preventDefault();
    });
    all("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (event) {
        if (!window.confirm(form.getAttribute("data-confirm") || "Weet je zeker dat je wilt doorgaan?")) event.preventDefault();
      });
    });
  }

  function dismissFlash(flash) {
    if (!flash) return;
    flash.classList.add("is-leaving");
    window.setTimeout(function () { flash.remove(); }, 210);
  }

  function setupFlashes() {
    all("[data-flash-close]").forEach(function (button) {
      button.addEventListener("click", function () { dismissFlash(button.closest(".flash")); });
    });
    all(".flash[data-auto-dismiss]").forEach(function (flash) {
      var delay = parseInt(flash.getAttribute("data-auto-dismiss"), 10) || 6000;
      window.setTimeout(function () { dismissFlash(flash); }, delay);
    });
  }

  function setupBulkSelection() {
    all("[data-select-all]").forEach(function (master) {
      var selector = master.getAttribute("data-select-all");
      master.addEventListener("change", function () {
        all(selector).forEach(function (box) { box.checked = master.checked; });
      });
    });
  }

  function setupFilters() {
    all("[data-table-filter]").forEach(function (input) {
      var table = document.querySelector(input.getAttribute("data-table-filter"));
      if (!table) return;
      input.addEventListener("input", function () {
        var query = input.value.toLocaleLowerCase().trim();
        all("tbody tr", table).forEach(function (row) {
          row.hidden = query && !row.textContent.toLocaleLowerCase().includes(query);
        });
      });
    });
  }

  function setupConditionalTargets() {
    all("[data-target-select]").forEach(function (select) {
      var form = select.closest("form");
      if (!form) return;
      function updateTarget() {
        all("[data-targets]", form).forEach(function (group) {
          var visible = group.getAttribute("data-targets").split(/\s+/).includes(select.value);
          group.hidden = !visible;
          all("input, select, textarea", group).forEach(function (field) { field.disabled = !visible; });
        });
        var scopeSelect = form.querySelector("[data-scm-scope-select]");
        if (scopeSelect && !scopeSelect.disabled) {
          all("[data-scm-scope]", form).forEach(function (group) {
            var visible = group.getAttribute("data-scm-scope") === scopeSelect.value;
            group.hidden = !visible;
            all("input", group).forEach(function (field) { field.disabled = !visible; });
          });
        }
      }
      select.addEventListener("change", updateTarget);
      updateTarget();
    });

    all("[data-scm-scope-select]").forEach(function (select) {
      var form = select.closest("form");
      function updateScope() {
        all("[data-scm-scope]", form).forEach(function (group) {
          var visible = group.getAttribute("data-scm-scope") === select.value;
          group.hidden = !visible;
          all("input", group).forEach(function (field) { field.disabled = !visible; });
        });
      }
      select.addEventListener("change", updateScope);
      updateScope();
    });
  }

  function setupPushOptions() {
    var forms = all("form[data-push-options]");
    if (!forms.length) return;

    var dialog = document.createElement("dialog");
    dialog.className = "push-dialog";
    dialog.innerHTML = '<div class="push-dialog-brand">OCD</div>' +
      '<div class="push-dialog-body"><h2>Security policies disabled pushen?</h2>' +
      '<div class="cluster push-dialog-actions">' +
      '<button class="btn btn-primary" type="button" data-push-choice="true">Ja</button>' +
      '<button class="btn" type="button" data-push-choice="false">Nee</button>' +
      '<button class="btn" type="button" data-push-cancel>Annuleren</button>' +
      '</div></div>';
    document.body.appendChild(dialog);
    var pendingForm = null;

    forms.forEach(function (form) {
      form.addEventListener("submit", function (event) {
        if (form.dataset.pushConfirmed === "true") {
          delete form.dataset.pushConfirmed;
          return;
        }
        event.preventDefault();
        pendingForm = form;
        dialog.showModal();
      });
    });

    all("[data-push-choice]", dialog).forEach(function (button) {
      button.addEventListener("click", function () {
        if (!pendingForm) return;
        var input = pendingForm.querySelector('input[name="disabled_override"]');
        if (!input) {
          input = document.createElement("input");
          input.type = "hidden";
          input.name = "disabled_override";
          pendingForm.appendChild(input);
        }
        input.value = button.getAttribute("data-push-choice");
        var form = pendingForm;
        pendingForm = null;
        form.dataset.pushConfirmed = "true";
        dialog.close();
        form.requestSubmit();
      });
    });
    dialog.querySelector("[data-push-cancel]").addEventListener("click", function () {
      pendingForm = null;
      dialog.close();
    });
    dialog.addEventListener("cancel", function () { pendingForm = null; });
  }

  document.addEventListener("DOMContentLoaded", function () {
    setupNavigation();
    setupPasswords();
    setupConfirmations();
    setupFlashes();
    setupBulkSelection();
    setupFilters();
    setupConditionalTargets();
    setupPushOptions();
  });
})();
