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

  function setupSidebarCollapse() {
    var button = document.querySelector("[data-sidebar-collapse]");
    if (!button) return;
    var collapsed = window.localStorage.getItem("ppf-sidebar-collapsed") === "true";
    function apply() { document.body.classList.toggle("sidebar-collapsed", collapsed); button.textContent = collapsed ? "›" : "‹"; button.title = collapsed ? "Navigatie uitklappen" : "Navigatie inklappen"; }
    button.addEventListener("click", function () { collapsed = !collapsed; window.localStorage.setItem("ppf-sidebar-collapsed", String(collapsed)); apply(); });
    apply();
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

  function setupPolicyManagement() {
    var rows = all("[data-policy-row]");
    var expression = document.querySelector("[data-policy-expression]");
    var filterStatus = document.querySelector("[data-policy-filter-status]");
    var fieldMap = {
      "name": "name", "rule": "name", "rule-type": "ruleType", "tag/member": "tag",
      "from/member": "from", "source/member": "source", "source-user/member": "sourceUser",
      "hip-profiles/member": "sourceHip", "source-hip/member": "sourceHip",
      "to/member": "to", "destination/member": "destination", "destination-user/member": "destinationUser",
      "destination-hip/member": "destinationHip", "application/member": "application",
      "service/member": "service", "category/member": "category", "action": "action",
      "disabled": "disabled", "log-start": "logStart", "log-end": "logEnd",
      "schedule": "schedule", "profile-setting/group/member": "profileGroup", "log-setting": "logSetting"
    };

    function tokenize(value) {
      return (value.match(/\(|\)|'[^']*'|"[^"]*"|[^\s()]+/g) || []).map(function (token) {
        if ((token[0] === "'" && token[token.length - 1] === "'") || (token[0] === '"' && token[token.length - 1] === '"')) return token.slice(1, -1);
        return token;
      });
    }

    function compileFilter(value) {
      var tokens = tokenize(value); var index = 0;
      function peek(word) { return (tokens[index] || "").toLowerCase() === word; }
      function primary() {
        if (peek("(")) { index += 1; var nested = orExpression(); if (!peek(")")) throw new Error("Ontbrekende )"); index += 1; return nested; }
        if (peek("not")) { index += 1; var negate = primary(); return function (row) { return !negate(row); }; }
        var field = tokens[index++];
        if (!field) throw new Error("Onvolledige filter");
        var operator = (tokens[index++] || "").toLowerCase();
        var expected = tokens[index++];
        if (!["eq", "neq", "contains"].includes(operator) || expected === undefined) throw new Error("Gebruik: veld eq 'waarde'");
        var dataField = fieldMap[field.toLowerCase()];
        if (!dataField) throw new Error("Onbekend veld: " + field);
        expected = expected.toLocaleLowerCase();
        return function (row) {
          var values = (row.dataset[dataField] || "").split("|||").map(function (item) { return item.toLocaleLowerCase(); });
          var match = operator === "contains" ? values.some(function (item) { return item.includes(expected); }) : values.some(function (item) { return item === expected; });
          return operator === "neq" ? !match : match;
        };
      }
      function andExpression() { let left = primary(); while (peek("and")) { index += 1; const right = primary(); const previous = left; left = function (row) { return previous(row) && right(row); }; } return left; }
      function orExpression() { let left = andExpression(); while (peek("or")) { index += 1; const right = andExpression(); const previous = left; left = function (row) { return previous(row) || right(row); }; } return left; }
      var result = orExpression();
      if (index !== tokens.length) throw new Error("Onverwacht filterdeel: " + tokens[index]);
      return result;
    }

    function applyFilter() {
      var query = expression ? expression.value.trim() : ""; var matcher = null;
      try { matcher = query ? compileFilter(query) : function () { return true; }; if (filterStatus) filterStatus.textContent = ""; }
      catch (error) { if (filterStatus) filterStatus.textContent = error.message; return; }
      var visible = 0;
      rows.forEach(function (row) { row.hidden = !matcher(row); if (!row.hidden) visible += 1; });
      if (filterStatus) filterStatus.textContent = visible + " policies";
    }
    if (expression) expression.addEventListener("input", applyFilter);

    var selectVisible = document.querySelector("[data-policy-select-visible]");
    if (selectVisible) selectVisible.addEventListener("change", function () {
      rows.forEach(function (row) {
        if (!row.hidden) row.querySelector("[data-policy-select]").checked = selectVisible.checked;
      });
      updateActionCount();
    });

    var lastSelectedIndex = null;
    function updateActionCount() {
      var count = all("[data-policy-select]:checked").length;
      var node = document.querySelector("[data-policy-action-count]");
      if (node) node.textContent = count;
    }
    rows.forEach(function (row, rowIndex) {
      var checkbox = row.querySelector("[data-policy-select]");
      checkbox.addEventListener("click", function (event) {
        if ((event.ctrlKey || event.shiftKey) && lastSelectedIndex !== null) {
          var start = Math.min(lastSelectedIndex, rowIndex); var end = Math.max(lastSelectedIndex, rowIndex);
          for (var i = start; i <= end; i += 1) rows[i].querySelector("[data-policy-select]").checked = true;
          checkbox.checked = true;
        }
      });
      checkbox.addEventListener("change", function () { lastSelectedIndex = rowIndex; updateActionCount(); });
      row.addEventListener("click", function (event) {
        if (event.target.closest("input,button,a,select")) return;
        if ((event.ctrlKey || event.shiftKey) && lastSelectedIndex !== null) {
          var start = Math.min(lastSelectedIndex, rowIndex); var end = Math.max(lastSelectedIndex, rowIndex);
          for (var i = start; i <= end; i += 1) rows[i].querySelector("[data-policy-select]").checked = true;
        } else checkbox.checked = !checkbox.checked;
        lastSelectedIndex = rowIndex; updateActionCount();
      });
    });

    var dialog = document.querySelector("[data-policy-bulk-dialog]");
    var opener = document.querySelector("[data-open-policy-bulk]");
    function selectedRows() { return rows.filter(function (row) { return row.querySelector("[data-policy-select]").checked; }); }
    function splitEntry(value) { return value.split(",").map(function (item) { return item.trim(); }).filter(Boolean); }
    function renderBulkField(fieldNode, values, removed, added) {
      var container = fieldNode.querySelector("[data-bulk-values]"); container.innerHTML = "";
      values.forEach(function (value) {
        var chip = document.createElement("span"); chip.className = "policy-value-chip" + (removed.has(value) ? " is-removed" : "");
        var label = document.createElement("span"); label.textContent = value; chip.appendChild(label);
        var button = document.createElement("button"); button.type = "button"; button.textContent = removed.has(value) ? "+" : "−";
        button.title = removed.has(value) ? "Verwijdering ongedaan maken" : "Uit geselecteerde policies verwijderen";
        button.addEventListener("click", function () {
          if (removed.has(value)) removed.delete(value); else removed.add(value);
          fieldNode.querySelector("[data-bulk-remove]").value = Array.from(removed).join(",");
          renderBulkField(fieldNode, values, removed, added);
        });
        chip.appendChild(button); container.appendChild(chip);
      });
      added.forEach(function (value) {
        var chip = document.createElement("span"); chip.className = "policy-value-chip is-added";
        var label = document.createElement("span"); label.textContent = value; chip.appendChild(label);
        var button = document.createElement("button"); button.type = "button"; button.textContent = "×"; button.title = "Toevoeging verwijderen";
        button.addEventListener("click", function () { added.delete(value); fieldNode.querySelector("[data-bulk-add]").value = Array.from(added).join(","); renderBulkField(fieldNode, values, removed, added); });
        chip.appendChild(button); container.appendChild(chip);
      });
      if (!values.length && !added.size) { var empty = document.createElement("span"); empty.className = "muted small"; empty.textContent = "Geen bestaande waarden"; container.appendChild(empty); }
    }
    function prepareBulkFields() {
      var selected = selectedRows(); var datasetKeys = {source_user: "sourceUser", destination_user: "destinationUser", source_hip: "sourceHip", destination_hip: "destinationHip"};
      all("[data-bulk-field]", dialog).forEach(function (fieldNode) {
        var field = fieldNode.dataset.bulkField; var dataKey = datasetKeys[field] || field; var values = []; var seen = new Set();
        selected.forEach(function (row) { (row.dataset[dataKey] || "").split("|||").filter(Boolean).forEach(function (value) { if (!seen.has(value)) { seen.add(value); values.push(value); } }); });
        var removed = new Set(); var added = new Set(); fieldNode._removedValues = removed; fieldNode._addedValues = added; fieldNode._currentValues = values;
        fieldNode.querySelector("[data-bulk-remove]").value = ""; fieldNode.querySelector("[data-bulk-add]").value = ""; fieldNode.querySelector("[data-bulk-entry]").value = "";
        renderBulkField(fieldNode, values, removed, added);
      });
    }
    if (dialog && opener) opener.addEventListener("click", function () {
      var count = all("[data-policy-select]:checked").length;
      if (!count) { window.alert("Selecteer minstens één security policy."); return; }
      dialog.querySelector("[data-policy-selected-count]").textContent = count;
      prepareBulkFields();
      dialog.showModal();
    });
    all("[data-bulk-field]", dialog).forEach(function (fieldNode) {
      var input = fieldNode.querySelector("[data-bulk-entry]"); var hidden = fieldNode.querySelector("[data-bulk-add]"); var button = fieldNode.querySelector("[data-bulk-add-button]");
      function addValue() {
        var additions = splitEntry(input.value); if (!additions.length) return;
        additions.forEach(function (value) { fieldNode._addedValues.add(value); });
        hidden.value = Array.from(fieldNode._addedValues).join(","); input.value = "";
        renderBulkField(fieldNode, fieldNode._currentValues, fieldNode._removedValues, fieldNode._addedValues);
      }
      button.addEventListener("click", addValue);
      input.addEventListener("keydown", function (event) { if (event.key === "Enter") { event.preventDefault(); addValue(); } });
    });
    all("[data-policy-tab]", dialog).forEach(function (tab) {
      tab.addEventListener("click", function () {
        all("[data-policy-tab]", dialog).forEach(function (item) { item.classList.toggle("is-active", item === tab); });
        all("[data-policy-panel]", dialog).forEach(function (panel) { panel.classList.toggle("is-active", panel.dataset.policyPanel === tab.dataset.policyTab); });
      });
    });
    var cancel = document.querySelector("[data-policy-bulk-cancel]");
    if (cancel) cancel.addEventListener("click", function () { dialog.close(); });
    applyFilter(); updateActionCount();
  }

  document.addEventListener("DOMContentLoaded", function () {
    setupNavigation();
    setupSidebarCollapse();
    setupPasswords();
    setupConfirmations();
    setupFlashes();
    setupBulkSelection();
    setupFilters();
    setupConditionalTargets();
    setupPushOptions();
    setupPolicyManagement();
  });
})();
