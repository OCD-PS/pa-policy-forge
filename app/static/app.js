(function () {
  "use strict";

  function all(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function parseTagTokens(value) {
    var tokens = []; var pattern = /'([^']*)'|"([^"]*)"|[^\s,]+/g; var match;
    while ((match = pattern.exec(String(value || ""))) !== null) {
      var token = (match[1] !== undefined ? match[1] : match[2] !== undefined ? match[2] : match[0]).trim();
      if (token && !tokens.includes(token)) tokens.push(token);
    }
    return tokens;
  }

  function tagQuoteOpen(value) {
    return ((String(value).match(/'/g) || []).length % 2 === 1) || ((String(value).match(/"/g) || []).length % 2 === 1);
  }

  var restoredPolicyBulkState = null;
  var policyBulkStateStorageKey = "ppf-unsaved-policy-bulk-state";

  function policyBulkControlKey(control) {
    if (control.name) return "name:" + control.name;
    var field = control.closest("[data-bulk-field],[data-bulk-scalar-field]");
    if (!field) return "";
    var fieldName = field.dataset.bulkField || field.dataset.bulkScalarField || "";
    if (control.hasAttribute("data-bulk-entry")) return "entry:" + fieldName;
    if (control.hasAttribute("data-bulk-scalar-entry")) return "scalar-entry:" + fieldName;
    return "";
  }

  function saveOpenPolicyBulkState() {
    var dialog = document.querySelector("[data-policy-bulk-dialog]");
    var form = dialog && dialog.closest("form[data-policy-bulk-form]");
    if (!dialog || !dialog.open || !form) return;
    try {
      var controls = all("input[name],select[name],textarea[name],[data-bulk-entry],[data-bulk-scalar-entry]", dialog).filter(function (control) {
        return control.name !== "csrf" && control.type !== "password";
      });
      var state = {
        url: window.location.href,
        selected: all("[data-policy-select]:checked", form).map(function (control) { return control.value; }),
        controls: controls.map(function (control) {
          return {
            key: policyBulkControlKey(control),
            name: control.name,
            type: control.type,
            value: control.multiple ? all("option", control).filter(function (option) { return option.selected; }).map(function (option) { return option.value; }) : control.value,
            checked: control.checked
          };
        }),
        activeTab: (dialog.querySelector("[data-policy-tab].is-active") || {}).dataset?.policyTab || ""
      };
      window.sessionStorage.setItem(policyBulkStateStorageKey, JSON.stringify(state));
    } catch (_) {}
  }

  function clearSavedPolicyBulkState() {
    try { window.sessionStorage.removeItem(policyBulkStateStorageKey); } catch (_) {}
  }

  function restorePolicyBulkState() {
    try {
      var raw = window.sessionStorage.getItem(policyBulkStateStorageKey);
      if (!raw) return;
      var state = JSON.parse(raw);
      if (!state || state.url !== window.location.href) return;
      window.sessionStorage.removeItem(policyBulkStateStorageKey);
      var dialog = document.querySelector("[data-policy-bulk-dialog]");
      var form = dialog && dialog.closest("form[data-policy-bulk-form]");
      if (!dialog || !form) return;
      var selected = new Set(state.selected || []);
      all("[data-policy-select]", form).forEach(function (control) { control.checked = selected.has(control.value); });
      var controls = all("input[name],select[name],textarea[name],[data-bulk-entry],[data-bulk-scalar-entry]", dialog).filter(function (control) {
        return control.name !== "csrf" && control.type !== "password";
      });
      (state.controls || []).forEach(function (saved, index) {
        var control = controls[index];
        if (!control || control.name !== saved.name || policyBulkControlKey(control) !== saved.key) return;
        if (control.type === "checkbox" || control.type === "radio") control.checked = Boolean(saved.checked);
        else if (control.multiple && Array.isArray(saved.value)) {
          all("option", control).forEach(function (option) { option.selected = saved.value.includes(option.value); });
        } else control.value = saved.value;
      });
      restoredPolicyBulkState = state;
    } catch (_) {
      try { window.sessionStorage.removeItem(policyBulkStateStorageKey); } catch (_) {}
    }
  }

  function setupPolicyBulkStatePersistence() {
    var submitting = false;
    var dialog = document.querySelector("[data-policy-bulk-dialog]");
    if (dialog) {
      dialog.addEventListener("cancel", clearSavedPolicyBulkState);
      dialog.addEventListener("close", clearSavedPolicyBulkState);
    }
    document.addEventListener("click", function (event) {
      if (event.target.closest("[data-policy-picker-create]")) saveOpenPolicyBulkState();
    });
    document.addEventListener("submit", function (event) {
      if (event.target.matches("form[data-policy-bulk-form]")) {
        submitting = true;
        try { window.sessionStorage.removeItem(policyBulkStateStorageKey); } catch (_) {}
      }
    }, true);
    window.addEventListener("pagehide", function () {
      if (!submitting) saveOpenPolicyBulkState();
    });
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
    all("[data-menu-toggle]").forEach(function (button) {
      button.addEventListener("click", function () { document.body.classList.toggle("nav-open"); });
    });

    // A review action must reveal its editor, even when that editor is folded.
    function revealAnchor(hash) {
      if (!hash || hash === "#") return;
      var target;
      try { target = document.getElementById(decodeURIComponent(hash.slice(1))); }
      catch (_) { return; }
      for (var node = target; node; node = node.parentElement) {
        if (node.tagName === "DETAILS") node.open = true;
      }
    }
    document.addEventListener("click", function (event) {
      var link = event.target.closest('a[href^="#"]');
      if (link && !event.defaultPrevented) revealAnchor(link.getAttribute("href"));
    });
    window.addEventListener("hashchange", function () { revealAnchor(window.location.hash); });
    revealAnchor(window.location.hash);
  }

  function setupSidebarCollapse() {
    var button = document.querySelector("[data-sidebar-collapse]");
    if (!button) return;
    var collapsed = window.localStorage.getItem("ppf-sidebar-collapsed") === "true";
    function apply() { document.body.classList.toggle("sidebar-collapsed", collapsed); button.textContent = collapsed ? "›" : "‹"; button.title = collapsed ? "Navigatie uitklappen" : "Navigatie inklappen"; }
    button.addEventListener("click", function () { collapsed = !collapsed; window.localStorage.setItem("ppf-sidebar-collapsed", String(collapsed)); apply(); });
    apply();
  }

  function setupConfigTree() {
    all("[data-config-tree]").forEach(function (tree) {
      var button = tree.querySelector("[data-config-tree-toggle]");
      if (!button) return;
      var collapsed = window.localStorage.getItem("ppf-config-tree-collapsed") === "true";
      function apply() {
        tree.classList.toggle("is-collapsed", collapsed);
        button.textContent = collapsed ? "›" : "‹";
        button.title = collapsed ? "Configuratiemenu uitklappen" : "Configuratiemenu inklappen";
      }
      button.addEventListener("click", function () {
        collapsed = !collapsed;
        window.localStorage.setItem("ppf-config-tree-collapsed", String(collapsed));
        apply();
      });
      apply();
    });
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
      var target = event.target.closest("[data-confirm]:not(form)");
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

  function updateTableRowVisibility(row) {
    row.hidden = row.dataset.tableTextMatch === "false" || row.dataset.tableFamilyMatch === "false";
  }

  function setupFilters() {
    all("[data-table-filter]").forEach(function (input) {
      var table = document.querySelector(input.getAttribute("data-table-filter"));
      if (!table) return;
      input.addEventListener("input", function () {
        var query = input.value.toLocaleLowerCase().trim();
        all("tbody tr", table).forEach(function (row) {
          row.dataset.tableTextMatch = String(!query || row.textContent.toLocaleLowerCase().includes(query));
          updateTableRowVisibility(row);
        });
      });
    });
  }

  function setupMigrationReviewSearch() {
    all("[data-migration-review-search]").forEach(function (input) {
      var container = input.closest(".migration-review-gate, .migration-output-review");
      if (!container) return;
      input.addEventListener("input", function () {
        var query = input.value.toLocaleLowerCase().trim();
        all("[data-migration-review-item]", container).forEach(function (item) {
          var text = item.getAttribute("data-review-text") || item.textContent || "";
          item.hidden = Boolean(query) && !text.toLocaleLowerCase().includes(query);
        });
      });
    });
  }

  function setupObjectSearchSubmit() {
    all('.workspace-object-search input[name="object_query"]').forEach(function (input) {
      var form = input.form;
      var submit = form && form.querySelector('button[type="submit"]:not([formaction])');
      if (!form || !submit) return;
      input.addEventListener("keydown", function (event) {
        if (event.key !== "Enter") return;
        event.preventDefault();
        form.requestSubmit(submit);
      });
    });
  }

  function setupMigrationFilterTypes() {
    all("[data-migration-filter-condition]").forEach(function (condition) {
      var field = condition.querySelector("[data-migration-filter-field]");
      var operator = condition.querySelector("[data-migration-filter-operator]");
      var textValue = condition.querySelector("[data-migration-filter-text]");
      var booleanValue = condition.querySelector("[data-migration-filter-boolean]");
      if (!field || !operator || !textValue || !booleanValue) return;
      var locked = field.disabled;
      function update() {
        var isBoolean = field.value === "disabled";
        textValue.hidden = isBoolean;
        textValue.disabled = locked || isBoolean;
        booleanValue.hidden = !isBoolean;
        booleanValue.disabled = locked || !isBoolean;
        all("option", operator).forEach(function (option) {
          option.disabled = isBoolean && option.value !== "equals";
        });
        if (isBoolean) operator.value = "equals";
      }
      field.addEventListener("change", update);
      update();
    });
  }

  function setupMigrationZoneMapping() {
    all("[data-migration-zone-form]").forEach(function (form) {
      all('select[name="from_zone"], select[name="to_zone"]', form).forEach(function (select) {
        select.multiple = true;
        select.size = Math.min(Math.max(select.options.length, 2), 6);
        select.addEventListener("mousedown", function (event) {
          if (event.target.tagName !== "OPTION") return;
          event.preventDefault();
          event.target.selected = !event.target.selected;
          select.focus();
        });
      });
      var checks = all("[data-migration-zone-select]", form);
      var master = form.querySelector("[data-migration-zone-select-visible]");
      var count = form.querySelector("[data-migration-zone-count]");
      var save = form.querySelector("[data-migration-zone-save]");
      function update() {
        var selected = checks.filter(function (check) { return check.checked; }).length;
        if (count) count.textContent = selected;
        if (save) save.disabled = selected === 0;
      }
      if (master) master.addEventListener("change", function () {
        checks.forEach(function (check) {
          var row = check.closest("tr");
          if (!row || !row.hidden) check.checked = master.checked;
        });
        update();
      });
      checks.forEach(function (check) { check.addEventListener("change", update); });
      update();
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
          var visible = !select.disabled && group.getAttribute("data-scm-scope") === select.value;
          group.hidden = !visible;
          all("input", group).forEach(function (field) { field.disabled = !visible; });
        });
      }
      select.addEventListener("change", updateScope);
      updateScope();
    });
  }

  function setupVsysMode() {
    all("[data-vsys-mode-select]").forEach(function (select) {
      var form = select.closest("form");
      if (!form) return;
      var countField = form.querySelector("[data-vsys-count-field]");
      var note = form.querySelector("[data-vsys-note]");
      var countSelect = form.querySelector("[data-vsys-count-select]");
      function update() {
        var multi = select.value === "multi";
        if (countField) countField.hidden = !multi;
        if (note) note.hidden = !multi;
        if (countSelect) countSelect.disabled = !multi;
      }
      select.addEventListener("change", update);
      update();
    });
  }

  function setupPushOptions() {
    var forms = all("form[data-push-options]");
    if (!forms.length) return;

    var dialog = document.createElement("dialog");
    dialog.className = "push-dialog";
    dialog.innerHTML = '<div class="push-dialog-brand">OCD</div>' +
      '<div class="push-dialog-body"><h2>Status van nieuwe security policies</h2>' +
      '<div class="cluster push-dialog-actions">' +
      '<button class="btn btn-primary" type="button" data-push-choice="true">Uitgeschakeld pushen</button>' +
      '<button class="btn" type="button" data-push-choice="false">Ingeschakeld pushen</button>' +
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
      "schedule": "schedule", "profile-setting/group/member": "profileGroup", "log-setting": "logSetting",
      "to-interface": "toInterface", "nat-type": "natType", "source-translation": "sourceTranslationSummary",
      "destination-translation": "destinationTranslationSummary"
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
        var checkbox = row.querySelector("[data-policy-select]");
        if (!row.hidden && checkbox) checkbox.checked = selectVisible.checked;
      });
      updateActionCount();
    });

    var lastSelectedIndex = null;
    function updateActionCount() {
      var count = all("[data-policy-select]:checked").length;
      var node = document.querySelector("[data-policy-action-count]");
      if (node) node.textContent = count;
      all("[data-policy-selection-action]").forEach(function (button) { button.disabled = !count; });
    }
    rows.forEach(function (row, rowIndex) {
      var checkbox = row.querySelector("[data-policy-select]");
      if (!checkbox) return;
      checkbox.addEventListener("click", function (event) {
        if ((event.ctrlKey || event.shiftKey) && lastSelectedIndex !== null) {
          var start = Math.min(lastSelectedIndex, rowIndex); var end = Math.max(lastSelectedIndex, rowIndex);
          for (var i = start; i <= end; i += 1) { var rangeCheckbox = rows[i].querySelector("[data-policy-select]"); if (!rows[i].hidden && rangeCheckbox) rangeCheckbox.checked = true; }
          checkbox.checked = true;
        }
      });
      checkbox.addEventListener("change", function () { lastSelectedIndex = rowIndex; updateActionCount(); });
      row.addEventListener("click", function (event) {
        if (event.target.closest("input,button,a,select")) return;
        if ((event.ctrlKey || event.shiftKey) && lastSelectedIndex !== null) {
          var start = Math.min(lastSelectedIndex, rowIndex); var end = Math.max(lastSelectedIndex, rowIndex);
          for (var i = start; i <= end; i += 1) { var rangeCheckbox = rows[i].querySelector("[data-policy-select]"); if (!rows[i].hidden && rangeCheckbox) rangeCheckbox.checked = true; }
        } else checkbox.checked = !checkbox.checked;
        lastSelectedIndex = rowIndex; updateActionCount();
      });
    });

    var singleDialog = document.querySelector("[data-policy-single-dialog]");
    if (singleDialog) {
      var singleTagInput = singleDialog.querySelector("[data-single-tag-input]"); var singleTagEntry = singleDialog.querySelector("[data-single-tag-entry]"); var singleTagSet = new Set();
      function renderSingleTags() { var container = singleDialog.querySelector("[data-single-tag-values]"); if (!container) return; container.innerHTML = ""; singleTagSet.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { singleTagSet.delete(value); singleTagInput.value = Array.from(singleTagSet).join(","); renderSingleTags(); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); }); if (!singleTagSet.size) { var empty = document.createElement("span"); empty.className = "muted small"; empty.textContent = "Geen tags"; container.appendChild(empty); } }
      function addSingleTags(value, exact) { (exact ? [value] : parseTagTokens(value)).forEach(function (tag) { if (tag) singleTagSet.add(tag); }); if (singleTagInput) singleTagInput.value = Array.from(singleTagSet).join(","); if (singleTagEntry) singleTagEntry.value = ""; renderSingleTags(); }
      if (singleTagEntry) { singleTagEntry._addTagValue = function (value) { addSingleTags(value, true); }; singleTagEntry._hasPickerValue = function (value) { return singleTagSet.has(value); }; singleTagEntry.addEventListener("keydown", function (event) { if (!singleTagEntry.readOnly && (event.key === "Enter" || event.key === "," || (event.key === " " && !tagQuoteOpen(singleTagEntry.value)))) { event.preventDefault(); addSingleTags(singleTagEntry.value, false); } }); }
      var singleTagAdd = singleDialog.querySelector("[data-single-tag-add]"); if (singleTagAdd) singleTagAdd.addEventListener("click", function () { addSingleTags(singleTagEntry.value); });
      var singleTokenFields = all("[data-single-token-field]", singleDialog);
      singleTokenFields.forEach(function (fieldNode) {
        var hidden = fieldNode.querySelector("[data-single-token-input]"); var entry = fieldNode.querySelector("[data-single-token-entry]"); var valuesNode = fieldNode.querySelector("[data-single-token-values]"); var valueSet = new Set();
        function syncSingleTokens() { hidden.value = Array.from(valueSet).join(","); valuesNode.innerHTML = ""; valueSet.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { valueSet.delete(value); syncSingleTokens(); }); chip.appendChild(label); chip.appendChild(remove); valuesNode.appendChild(chip); }); if (!valueSet.size) { var empty = document.createElement("span"); empty.className = "muted small"; empty.textContent = "Geen waarden"; valuesNode.appendChild(empty); } }
        function addSingleToken(value) { var additions = value.split(",").map(function (item) { return item.trim(); }).filter(Boolean); if (fieldNode.dataset.tokenCardinality === "one" && additions.length) valueSet.clear(); additions.forEach(function (item) { valueSet.add(item); }); entry.value = ""; syncSingleTokens(); }
        fieldNode._setTokenValues = function (values) { valueSet = new Set(Array.isArray(values) ? values : values ? [values] : []); syncSingleTokens(); };
        entry._addTokenValue = addSingleToken; entry._hasPickerValue = function (value) { return valueSet.has(value); }; entry.addEventListener("keydown", function (event) { if (event.key === "Enter" || event.key === ",") { event.preventDefault(); addSingleToken(entry.value); } });
        fieldNode.querySelector("[data-single-token-add]").addEventListener("click", function () { addSingleToken(entry.value); }); syncSingleTokens();
      });
      var singleForm = singleDialog.querySelector("[data-policy-single-form]"); if (singleForm) singleForm.addEventListener("submit", function () { if (singleTagEntry && !singleTagEntry.readOnly && singleTagEntry.value.trim()) addSingleTags(singleTagEntry.value, false); singleTokenFields.forEach(function (fieldNode) { var entry = fieldNode.querySelector("[data-single-token-entry]"); if (entry.value.trim()) entry._addTokenValue(entry.value); }); });
      rows.forEach(function (row) {
        var button = row.querySelector("[data-policy-edit]");
        if (!button) return;
        button.addEventListener("click", function () {
          var policy = JSON.parse(row.dataset.policy);
          singleDialog.querySelector("[data-single-policy-id]").value = policy.id;
          singleDialog.querySelector("[data-single-policy-title]").textContent = policy.name;
          all("[data-single-field]", singleDialog).forEach(function (field) {
            var value = policy[field.dataset.singleField];
            if (Array.isArray(value)) value = value.join(", ");
            if (field.dataset.singleField === "disabled") value = value ? "true" : "false";
            field.value = value === undefined || value === null ? "" : value;
          });
          singleTokenFields.forEach(function (fieldNode) { fieldNode._setTokenValues(policy[fieldNode.dataset.singleTokenField]); });
          singleTagSet = new Set(Array.isArray(policy.tag) ? policy.tag : []); if (singleTagInput) singleTagInput.value = Array.from(singleTagSet).join(","); renderSingleTags();
          all("[data-single-tab]", singleDialog).forEach(function (tab, index) { tab.classList.toggle("is-active", index === 0); });
          all("[data-single-panel]", singleDialog).forEach(function (panel, index) { panel.classList.toggle("is-active", index === 0); });
          singleDialog.showModal();
        });
      });
      all("[data-single-tab]", singleDialog).forEach(function (tab) {
        tab.addEventListener("click", function () {
          all("[data-single-tab]", singleDialog).forEach(function (item) { item.classList.toggle("is-active", item === tab); });
          all("[data-single-panel]", singleDialog).forEach(function (panel) { panel.classList.toggle("is-active", panel.dataset.singlePanel === tab.dataset.singleTab); });
        });
      });
      singleDialog.querySelector("[data-policy-single-cancel]").addEventListener("click", function () { singleDialog.close(); });
    }

    var offlineExclusivePicker = document.querySelector("[data-offline-policy-dialog]");
    var valuePicker = offlineExclusivePicker ? null : document.querySelector("[data-policy-value-picker]"); var policyCatalogNode = document.querySelector("[data-policy-catalog]");
    if (valuePicker && policyCatalogNode) {
      var policyCatalog = JSON.parse(policyCatalogNode.textContent || "[]"); var pickerTarget = null; var pickerSelections = new Set();
      var bulkFormForCatalog = document.querySelector("[data-policy-bulk-form]"); var catalogFormAction = bulkFormForCatalog ? (bulkFormForCatalog.getAttribute("action") || "") : ""; var catalogProfileMatch = catalogFormAction.match(/\/policies\/(\d+)\/preview/); var workspaceApplicationState = document.querySelector("[data-workspace-application-catalog]"); var applicationPolls = 0;
      var pickerKinds = {from:["zones"],to:["zones"],source:["addresses","address-groups","regions"],destination:["addresses","address-groups","regions"],application:["applications","application-groups","application-filters"],service:["services","service-groups"],tag:["tags"],source_user:["$current"],destination_user:["$current"],source_hip:["hip-profiles"],destination_hip:["hip-profiles"],category:["custom-url-categories","predefined-url-categories"],schedule:["schedules"],log_setting:["log-forwarding"],profile_group:["security-profile-groups"],to_interface:["interfaces"],source_translation_address:["addresses","address-groups"],source_translation_interface:["interfaces"],destination_translation_address:["addresses","address-groups"]};
      var createKinds = {from:"zones",to:"zones",source:"addresses",destination:"addresses",application:"application-groups",service:"services",tag:"tags",category:"custom-url-categories",log_setting:"log-forwarding",profile_group:"security-profile-groups",source_translation_address:"addresses",destination_translation_address:"addresses"};
      function addPickedValue(name) { if (!pickerTarget) return; if (typeof pickerTarget._addTagValue === "function") { pickerTarget._addTagValue(name); } else if (typeof pickerTarget._addTokenValue === "function") { pickerTarget._addTokenValue(name); } else if (typeof pickerTarget._addScalarValue === "function") { pickerTarget._addScalarValue(name); } else if (pickerTarget.hasAttribute("data-bulk-entry")) { pickerTarget.value = name; pickerTarget.closest("[data-bulk-field]").querySelector("[data-bulk-add-button]").click(); } else { pickerTarget.value = name; } }
      function updatePickerCount() { var count = valuePicker.querySelector("[data-policy-picker-selected-count]"); if (count) count.textContent = pickerSelections.size; }
      function renderPolicyPicker(query) { var field = pickerTarget ? pickerTarget.dataset.pickerField : ""; var kinds = pickerKinds[field] || []; var candidates = policyCatalog.filter(function (item) { return kinds.includes(item.kind); }); if (kinds.includes("$current")) { var datasetKeys = {source_user:"sourceUser",destination_user:"destinationUser",source_hip:"sourceHip",destination_hip:"destinationHip",profile_group:"profileGroup",log_setting:"logSetting"}; var key = datasetKeys[field] || field; var seen = new Set(); rows.forEach(function (policyRow) { (policyRow.dataset[key] || "").split("|||").filter(Boolean).forEach(function (name) { if (!seen.has(name)) { seen.add(name); candidates.push({name:name,kind:"huidige rulebase"}); } }); }); } var results = valuePicker.querySelector("[data-policy-picker-results]"); results.innerHTML = ""; candidates.filter(function (item) { return (!pickerTarget || typeof pickerTarget._hasPickerValue !== "function" || !pickerTarget._hasPickerValue(item.name)) && (!query || item.name.toLocaleLowerCase().includes(query)); }).forEach(function (item) { var row = document.createElement("div"); row.className = "member-result" + (pickerSelections.has(item.name) ? " is-selected" : ""); var copy = document.createElement("div"); var strong = document.createElement("strong"); strong.textContent = item.name; var small = document.createElement("small"); small.textContent = item.kind; copy.appendChild(strong); copy.appendChild(small); var button = document.createElement("button"); button.className = "btn btn-small"; button.type = "button"; button.textContent = pickerSelections.has(item.name) ? "Geselecteerd" : "Selecteer"; function toggleSelection() { if (pickerSelections.has(item.name)) pickerSelections.delete(item.name); else { if (pickerTarget && pickerTarget.dataset.pickerCardinality === "one") pickerSelections.clear(); pickerSelections.add(item.name); } updatePickerCount(); renderPolicyPicker(query); } button.addEventListener("click", function (event) { event.stopPropagation(); toggleSelection(); }); row.addEventListener("click", toggleSelection); row.appendChild(copy); row.appendChild(button); results.appendChild(row); }); if (!results.children.length) { var empty = document.createElement("div"); empty.className = "muted member-result"; empty.textContent = "Geen bestaand compatibel object gevonden."; results.appendChild(empty); } updatePickerCount(); }
      function showApplicationError(message) { if (!message || !pickerTarget || pickerTarget.dataset.pickerField !== "application") return; var results = valuePicker.querySelector("[data-policy-picker-results]"); var warning = document.createElement("div"); warning.className = "callout member-result"; warning.textContent = "Applicatiecatalogus niet bijgewerkt: " + message; results.prepend(warning); }
      function showApplicationStatus(data) { var status = valuePicker.querySelector("[data-policy-picker-status]"); if (!status) return; status.textContent = data.error ? "Applicatiecatalogus kon niet worden bijgewerkt." : data.ready ? data.items.length + " applicaties beschikbaar." : data.refreshing ? "Application database wordt geladen…" : "Geen application database beschikbaar."; }
      function loadApplications() { var catalogUrl = catalogProfileMatch ? "/profiles/" + catalogProfileMatch[1] + "/catalog/applications" : workspaceApplicationState ? workspaceApplicationState.dataset.workspaceApplicationCatalog : ""; if (!catalogUrl) return; var initialStatus = valuePicker.querySelector("[data-policy-picker-status]"); if (initialStatus) initialStatus.textContent = "Application database wordt geladen…"; fetch(catalogUrl, {headers:{"Accept":"application/json"}}).then(function (response) { if (!response.ok) throw new Error("HTTP " + response.status); return response.json(); }).then(function (data) { var existing = new Set(policyCatalog.filter(function (item) { return item.kind === "applications"; }).map(function (item) { return item.name; })); (data.items || []).forEach(function (item) { if (!existing.has(item.name)) policyCatalog.push(item); }); showApplicationStatus(data); if (pickerTarget && pickerTarget.dataset.pickerField === "application") { renderPolicyPicker((valuePicker.querySelector("[data-policy-picker-filter]").value || "").toLocaleLowerCase()); showApplicationError(data.error); } if (!data.ready && data.refreshing && applicationPolls < 40) { applicationPolls += 1; setTimeout(loadApplications, 3000); } }).catch(function (error) { showApplicationError(error.message); }); }
      function updateCreateObjectLink(field) { var row = valuePicker.querySelector("[data-policy-picker-create-row]"); var link = valuePicker.querySelector("[data-policy-picker-create]"); var kind = createKinds[field]; if (!row || !link || !kind) { if (row) row.hidden = true; return; } var workspaceForm = document.querySelector("[data-offline-policy-dialog] form"); if (workspaceForm) { var workspaceMatch = (workspaceForm.getAttribute("action") || "").match(/\/config-workspaces\/(\d+)\//); var scope = workspaceForm.querySelector('[name="scope"]'); if (!workspaceMatch) { row.hidden = true; return; } link.href = "/config-workspaces/" + workspaceMatch[1] + "/edit?scope=" + encodeURIComponent(scope ? scope.value : "") + "&workspace_view=" + (kind === "zones" ? "network&config_section=zones" : "objects&object_type=" + encodeURIComponent(kind) + "&add_object=1"); } else if (catalogProfileMatch) link.href = "/?policy_profile=" + catalogProfileMatch[1] + "&policy_view=objects&object_type=" + encodeURIComponent(kind) + "&add_object=1#policy-management"; else { row.hidden = true; return; } row.hidden = false; }
      function openPolicyValuePicker(input, fieldName) { pickerTarget = input; pickerTarget.dataset.pickerField = fieldName || input.dataset.pickerField; pickerSelections.clear(); var pickerStatus = valuePicker.querySelector("[data-policy-picker-status]"); if (pickerStatus) pickerStatus.textContent = ""; var activeDialog = input.closest("dialog"); if (activeDialog && valuePicker.parentElement !== activeDialog) activeDialog.appendChild(valuePicker); valuePicker.hidden = false; valuePicker.querySelector("[data-policy-picker-title]").textContent = "Bestaande waarden voor " + pickerTarget.dataset.pickerField.replace(/_/g, " "); var filter = valuePicker.querySelector("[data-policy-picker-filter]"); filter.value = ""; updateCreateObjectLink(pickerTarget.dataset.pickerField); renderPolicyPicker(""); if (pickerTarget.dataset.pickerField === "application") { applicationPolls = 0; loadApplications(); } }
      all("[data-picker-field]").forEach(function (input) {
        if (!pickerKinds[input.dataset.pickerField]) return;
        if (input.readOnly) input.addEventListener("focus", function () { openPolicyValuePicker(input); });
        input.addEventListener("input", function () { if (pickerTarget === input && !input.readOnly) valuePicker.hidden = true; });
      });
      all("[data-bulk-picker-button]").forEach(function (button) {
        var input = button.closest(".token-input") && button.closest(".token-input").querySelector("[data-picker-field]");
        if (input) button.addEventListener("click", function () { openPolicyValuePicker(input); });
      });
      var singleTagPicker = document.querySelector("[data-single-tag-picker]"); if (singleTagPicker && singleTagEntry) singleTagPicker.addEventListener("click", function () { openPolicyValuePicker(singleTagEntry, "tag"); });
      valuePicker.querySelector("[data-policy-picker-filter]").addEventListener("input", function (event) { renderPolicyPicker(event.target.value.toLocaleLowerCase().trim()); });
      valuePicker.querySelector("[data-policy-picker-close]").addEventListener("click", function () { valuePicker.hidden = true; });
      var addSelected = valuePicker.querySelector("[data-policy-picker-add-selected]"); if (addSelected) addSelected.addEventListener("click", function () { pickerSelections.forEach(addPickedValue); pickerSelections.clear(); updatePickerCount(); valuePicker.hidden = true; });
      all("[data-bulk-add-button],[data-single-token-add],[data-bulk-scalar-choose]").forEach(function (button) { var input = button.closest(".token-input") && button.closest(".token-input").querySelector("[data-picker-field]"); if (input && input.readOnly) button.addEventListener("click", function () { openPolicyValuePicker(input); }); });
    }

    var dialog = document.querySelector("[data-policy-bulk-dialog]");
    var opener = document.querySelector("[data-open-policy-bulk]");
    function prepareBulkScalars(preserve) {
      all("[data-bulk-scalar-field]", dialog).forEach(function (fieldNode) {
        var hidden = fieldNode.querySelector("[data-bulk-scalar-value]");
        var entry = fieldNode.querySelector("[data-bulk-scalar-entry]");
        var values = fieldNode.querySelector("[data-bulk-scalar-values]");
        function render(value) {
          values.innerHTML = "";
          if (!value) {
            var keep = document.createElement("span"); keep.className = "muted small"; keep.textContent = "Behouden"; values.appendChild(keep); return;
          }
          var chip = document.createElement("span"); chip.className = "policy-value-chip is-added";
          var label = document.createElement("span"); label.textContent = value;
          var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.title = "Vervanging annuleren";
          remove.addEventListener("click", function () { hidden.value = ""; render(""); });
          chip.appendChild(label); chip.appendChild(remove); values.appendChild(chip);
        }
        entry._addScalarValue = function (value) { hidden.value = String(value || "").trim(); entry.value = ""; render(hidden.value); };
        entry._hasPickerValue = function (value) { return hidden.value === value; };
        if (!preserve) hidden.value = "";
        render(hidden.value);
      });
    }
    function selectedRows() { return rows.filter(function (row) { var checkbox = row.querySelector("[data-policy-select]"); return checkbox && checkbox.checked; }); }
    function splitEntry(value, field) { return field === "tag" ? parseTagTokens(value) : value.split(",").map(function (item) { return item.trim(); }).filter(Boolean); }
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
    function prepareBulkFields(preserve) {
      var selected = selectedRows(); var datasetKeys = {source_user: "sourceUser", destination_user: "destinationUser", source_hip: "sourceHip", destination_hip: "destinationHip"};
      all("[data-bulk-field]", dialog).forEach(function (fieldNode) {
        var field = fieldNode.dataset.bulkField; var dataKey = datasetKeys[field] || field; var values = []; var seen = new Set();
        selected.forEach(function (row) { (row.dataset[dataKey] || "").split("|||").filter(Boolean).forEach(function (value) { if (!seen.has(value)) { seen.add(value); values.push(value); } }); });
        var removeInput = fieldNode.querySelector("[data-bulk-remove]"); var addInput = fieldNode.querySelector("[data-bulk-add]");
        var removed = new Set(preserve ? splitEntry(removeInput.value, field) : []); var added = new Set(preserve ? splitEntry(addInput.value, field) : []);
        fieldNode._removedValues = removed; fieldNode._addedValues = added; fieldNode._currentValues = values;
        if (!preserve) { removeInput.value = ""; addInput.value = ""; fieldNode.querySelector("[data-bulk-entry]").value = ""; }
        renderBulkField(fieldNode, values, removed, added);
      });
    }
    if (dialog && opener) opener.addEventListener("click", function () {
      var count = all("[data-policy-select]:checked").length;
      if (!count) { window.alert("Selecteer minstens één policy."); return; }
      dialog.querySelector("[data-policy-selected-count]").textContent = count;
      prepareBulkFields(false);
      prepareBulkScalars(false);
      dialog.showModal();
    });
    all("[data-bulk-field]", dialog).forEach(function (fieldNode) {
      var input = fieldNode.querySelector("[data-bulk-entry]"); input._hasPickerValue = function (value) { return Boolean(fieldNode._addedValues && fieldNode._addedValues.has(value)); }; var hidden = fieldNode.querySelector("[data-bulk-add]"); var button = fieldNode.querySelector("[data-bulk-add-button]");
      function addValue(exactValue) {
        var additions = exactValue === undefined ? splitEntry(input.value, fieldNode.dataset.bulkField) : [exactValue]; if (!additions.length) return;
        additions.forEach(function (value) { fieldNode._addedValues.add(value); });
        hidden.value = Array.from(fieldNode._addedValues).join(","); input.value = "";
        renderBulkField(fieldNode, fieldNode._currentValues, fieldNode._removedValues, fieldNode._addedValues);
      }
      fieldNode._addBulkValue = addValue;
      input._addTokenValue = function (value) { addValue(value); };
      button.addEventListener("click", function () { if (!input.readOnly) addValue(); });
      input.addEventListener("keydown", function (event) { var tagDelimiter = fieldNode.dataset.bulkField === "tag" && (event.key === "," || (event.key === " " && !tagQuoteOpen(input.value))); if (event.key === "Enter" || tagDelimiter) { event.preventDefault(); addValue(); } });
    });
    function showPolicyOperationProgress(event) {
      var form = event.target;
      var button = event.submitter;
      if (!button || button.disabled) return;
      var isDelete = button.hasAttribute("data-policy-delete");
      var bulkDialog = form.closest("[data-policy-bulk-dialog]");
      var isBulkList = form.matches("[data-policy-bulk-form]");
      if (!isDelete && !bulkDialog && !isBulkList) return;
      if (!isDelete && button.hasAttribute("data-policy-selection-action")) return;
      button.disabled = true;
      button.textContent = isDelete ? "Verwijderen..." : "Opslaan...";
      form.setAttribute("aria-busy", "true");
      var status = document.createElement("div");
      status.className = "bulk-operation-status help";
      status.setAttribute("role", "status");
      status.setAttribute("aria-live", "polite");
      status.textContent = isDelete ? "Policies worden verwijderd..." : "Bulkbewerking wordt verwerkt...";
      var bar = document.createElement("div");
      bar.className = "progress";
      bar.setAttribute("aria-hidden", "true");
      var fill = document.createElement("div");
      fill.className = "progress-bar progress-indeterminate";
      bar.appendChild(fill);
      status.appendChild(bar);
      var host = bulkDialog ? bulkDialog.querySelector(".bulk-dialog-actions") : button.closest(".policy-actionbar, .object-actionbar");
      if (!host) host = form;
      host.insertAdjacentElement("afterend", status);
    }
    document.addEventListener("submit", showPolicyOperationProgress);
    var policyBulkForm = document.querySelector("[data-policy-bulk-form]"); if (policyBulkForm) policyBulkForm.addEventListener("submit", function () { all("[data-bulk-field]", dialog).forEach(function (fieldNode) { var entry = fieldNode.querySelector("[data-bulk-entry]"); if (entry && entry.value.trim()) fieldNode._addBulkValue(); }); });
    var policyDelete = document.querySelector("[data-policy-delete]"); if (policyDelete) policyDelete.addEventListener("click", function (event) { if (!window.confirm("Geselecteerde policies verwijderen?")) event.preventDefault(); });
    all("[data-policy-tab]", dialog).forEach(function (tab) {
      tab.addEventListener("click", function () {
        all("[data-policy-tab]", dialog).forEach(function (item) { item.classList.toggle("is-active", item === tab); });
        all("[data-policy-panel]", dialog).forEach(function (panel) { panel.classList.toggle("is-active", panel.dataset.policyPanel === tab.dataset.policyTab); });
      });
    });
    var cancel = document.querySelector("[data-policy-bulk-cancel]");
    if (cancel) cancel.addEventListener("click", function () { dialog.close(); });
    if (dialog && restoredPolicyBulkState) {
      var restoredCount = selectedRows().length;
      if (restoredCount) {
        dialog.querySelector("[data-policy-selected-count]").textContent = restoredCount;
        prepareBulkFields(true);
        prepareBulkScalars(true);
        var activeTab = restoredPolicyBulkState.activeTab;
        if (activeTab) {
          all("[data-policy-tab]", dialog).forEach(function (tab) { tab.classList.toggle("is-active", tab.dataset.policyTab === activeTab); });
          all("[data-policy-panel]", dialog).forEach(function (panel) { panel.classList.toggle("is-active", panel.dataset.policyPanel === activeTab); });
        }
        dialog.showModal();
      }
      restoredPolicyBulkState = null;
    }
    applyFilter(); updateActionCount();
  }

  function setupObjectManagement() {
    var dialog = document.querySelector("[data-object-dialog]");
    var form = document.querySelector("[data-object-form]");
    if (dialog) { var objectTabs = dialog.querySelector(".policy-tabs"); if (objectTabs && objectTabs.querySelectorAll("button:not([disabled])").length <= 1) objectTabs.remove(); }
    var rows = all("[data-object-row]");
    var checkboxes = all("[data-object-select]");
    var countNode = document.querySelector("[data-object-selected-count]");
    var deleteButtons = all("[data-object-delete]");
    var deleteButton = deleteButtons[0] || null;
    function updateCount() { var count = checkboxes.filter(function (item) { return item.checked; }).length; if (countNode) countNode.textContent = count; deleteButtons.forEach(function (button) { button.disabled = !count; }); }
    checkboxes.forEach(function (checkbox) { checkbox.addEventListener("change", updateCount); });
    var master = document.querySelector("[data-object-select-visible]");
    if (master) master.addEventListener("change", function () { rows.forEach(function (row) { var checkbox = row.querySelector("[data-object-select]"); if (checkbox && !row.hidden) checkbox.checked = master.checked; }); updateCount(); });
    var detailDialog = document.querySelector("[data-object-detail-dialog]");
    if (detailDialog) {
      rows.forEach(function (row) { var button = row.querySelector("[data-object-detail]"); if (!button) return; var item = JSON.parse(row.dataset.object); button.addEventListener("click", function () { detailDialog.querySelector("[data-object-detail-title]").textContent = item.name; var body = detailDialog.querySelector("[data-object-detail-body]"); body.innerHTML = ""; Object.keys(item).filter(function (key) { return key.charAt(0) !== "_"; }).sort().forEach(function (key) { var tr = document.createElement("tr"); var name = document.createElement("td"); name.textContent = key; var value = document.createElement("td"); value.className = "mono"; value.textContent = typeof item[key] === "object" ? JSON.stringify(item[key]) : item[key]; tr.appendChild(name); tr.appendChild(value); body.appendChild(tr); }); detailDialog.showModal(); }); });
      detailDialog.querySelector("[data-object-detail-close]").addEventListener("click", function () { detailDialog.close(); });
    }
    if (!dialog || !form) { updateCount(); return; }
    var currentObjectType = (form.querySelector('[name="object_type"]') || {}).value || "";
    var groupType = form.querySelector("[data-object-group-type]");
    function updateGroupType() { if (!groupType) return; var dynamic = groupType.value === "dynamic"; var staticNode = form.querySelector("[data-static-members]"); var dynamicNode = form.querySelector("[data-dynamic-filter]"); if (staticNode) staticNode.hidden = dynamic; if (dynamicNode) dynamicNode.hidden = !dynamic; }
    if (groupType) groupType.addEventListener("change", updateGroupType);
    var override = form.querySelector("[data-service-override]");
    function updateTimeouts() { all("[data-timeout-field]", form).forEach(function (node) { node.hidden = !(override && override.checked); }); }
    if (override) override.addEventListener("change", updateTimeouts);
    var memberInput = form.querySelector("[data-member-input]"); var memberSet = new Set();
    function renderMembers() { var container = form.querySelector("[data-member-values]"); if (!container) return; container.innerHTML = ""; memberSet.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.title = "Member verwijderen"; remove.addEventListener("click", function () { memberSet.delete(value); memberInput.value = Array.from(memberSet).join(","); renderMembers(); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); }); if (!memberSet.size) { var empty = document.createElement("span"); empty.className = "muted small"; empty.textContent = "Geen members"; container.appendChild(empty); } }
    function setMembers(values) { memberSet = new Set(Array.isArray(values) ? values : (values ? String(values).split(",").map(function (value) { return value.trim(); }).filter(Boolean) : [])); if (memberInput) memberInput.value = Array.from(memberSet).join(","); renderMembers(); }
    var tagInput = form.querySelector("[data-object-tag-input]"); var tagSet = new Set();
    function renderTags() { var container = form.querySelector("[data-object-tag-values]"); if (!container) return; container.innerHTML = ""; tagSet.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.title = "Tag verwijderen"; remove.addEventListener("click", function () { tagSet.delete(value); if (tagInput) tagInput.value = Array.from(tagSet).join(","); renderTags(); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); }); if (!tagSet.size) { var empty = document.createElement("span"); empty.className = "muted small"; empty.textContent = "Geen tags"; container.appendChild(empty); } }
    function setTags(values) { tagSet = new Set(Array.isArray(values) ? values : (values ? String(values).split(",").map(function (value) { return value.trim(); }).filter(Boolean) : [])); if (tagInput) tagInput.value = Array.from(tagSet).join(","); renderTags(); }
    var zoneReferenceFields = all("[data-zone-reference-field]", form);
    function zoneReferenceValues(field) { if (!field._zoneReferenceValues) field._zoneReferenceValues = new Set(); return field._zoneReferenceValues; }
    function renderZoneReference(field) { var values = zoneReferenceValues(field); var container = field.querySelector("[data-zone-reference-values]"); var hidden = field.querySelector("[data-zone-reference-input]"); if (!container || !hidden) return; container.innerHTML = ""; values.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { values.delete(value); hidden.value = Array.from(values).join(","); renderZoneReference(field); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); }); if (!values.size) { var empty = document.createElement("span"); empty.className = "muted small"; empty.textContent = "Geen waarde geselecteerd"; container.appendChild(empty); } hidden.value = Array.from(values).join(","); }
    function setZoneReference(name, values) { var field = form.querySelector('[data-zone-reference-field="' + name + '"]'); if (!field) return; var normalized = Array.isArray(values) ? values : (values ? String(values).split(",").map(function (value) { return value.trim(); }).filter(Boolean) : []); if (field.dataset.zoneReferenceCardinality === "one") normalized = normalized.slice(0, 1); field._zoneReferenceValues = new Set(normalized); renderZoneReference(field); }
    var dynamicInput = form.querySelector("[data-dynamic-input]"); var dynamicEntry = form.querySelector("[data-dynamic-entry]"); var dynamicTokens = [];
    function dynamicExpressionTokens(value) { return String(value || "").match(/'[^']*'|"[^"]*"|\(|\)|[^\s()]+/g) || []; }
    function renderDynamicTokens() { var container = form.querySelector("[data-dynamic-values]"); if (!container) return; container.innerHTML = ""; dynamicTokens.forEach(function (value, index) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.title = "Expressiedeel verwijderen"; remove.addEventListener("click", function () { dynamicTokens.splice(index, 1); syncDynamicFilter(); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); }); }
    function syncDynamicFilter() { if (dynamicInput) dynamicInput.value = dynamicTokens.join(" "); renderDynamicTokens(); }
    function setDynamicFilter(value) { dynamicTokens = dynamicExpressionTokens(value); if (dynamicEntry) dynamicEntry.value = ""; syncDynamicFilter(); }
    function dynamicQuoteOpen(value) { var single = (value.match(/'/g) || []).length; var double = (value.match(/"/g) || []).length; return single % 2 === 1 || double % 2 === 1; }
    function commitDynamicEntry() { if (!dynamicEntry) return; var value = dynamicEntry.value.trim(); if (!value) return; dynamicTokens = dynamicTokens.concat(dynamicExpressionTokens(value)); dynamicEntry.value = ""; syncDynamicFilter(); }
    if (dynamicEntry) dynamicEntry.addEventListener("keydown", function (event) { if ((event.key === " " && !dynamicQuoteOpen(dynamicEntry.value)) || event.key === "Enter") { event.preventDefault(); commitDynamicEntry(); } });
    function setField(name, value) { var field = form.querySelector('[data-object-field="' + name + '"]'); if (!field) return; field.value = Array.isArray(value) ? value.join(", ") : (value == null ? "" : value); }
    var genericEditor = dialog.dataset.genericObjectEditor === "true" || Boolean(document.querySelector('[data-object-create-template][data-object-generic="true"]'));
    var genericUpdates = [];
    var genericCatalogList = null; var genericCatalogLoaded = false;
    function loadGenericUrlCatalog() {
      if (genericCatalogLoaded) return; genericCatalogLoaded = true;
      var title = (document.querySelector(".object-list h2") || {}).textContent || ""; if (!/URL Filtering/i.test(title)) return;
      var action = form.getAttribute("action") || ""; var url = ""; var workspaceMatch = action.match(/\/config-workspaces\/(\d+)\/objects\/preview/); var scmMatch = action.match(/\/objects\/(\d+)\/url-filtering\/preview/);
      if (workspaceMatch) { var scope = form.querySelector('[name="scope"]'); url = "/config-workspaces/" + workspaceMatch[1] + "/catalog/url-categories?scope=" + encodeURIComponent(scope ? scope.value : ""); }
      else if (scmMatch) url = "/profiles/" + scmMatch[1] + "/catalog/url-categories";
      if (!url) return;
      genericCatalogList = document.createElement("datalist"); genericCatalogList.id = "url-category-catalog-" + Math.random().toString(36).slice(2); form.appendChild(genericCatalogList);
      fetch(url, {headers:{"Accept":"application/json"}}).then(function (response) { if (!response.ok) throw new Error("HTTP " + response.status); return response.json(); }).then(function (data) { genericCatalogList.innerHTML = ""; (data.items || []).forEach(function (item) { var option = document.createElement("option"); option.value = item.name; option.label = item.kind || "URL category"; genericCatalogList.appendChild(option); }); }).catch(function () { genericCatalogList.remove(); genericCatalogList = null; });
    }
    function syncGenericUpdates() { var target = form.querySelector("[data-generic-object-updates]"); if (target) target.value = JSON.stringify(genericUpdates); }
    function renderGenericFields(item) {
      var container = form.querySelector("[data-generic-object-fields]");
      if (!container) { var hidden = document.createElement("input"); hidden.type = "hidden"; hidden.name = "generic_updates"; hidden.dataset.genericObjectUpdates = ""; form.appendChild(hidden); container = document.createElement("div"); container.className = "generic-object-fields full"; container.dataset.genericObjectFields = ""; form.querySelector(".form-grid").appendChild(container); }
      var tabs = dialog.querySelector(".policy-tabs"); if (!tabs) { tabs = document.createElement("div"); tabs.className = "policy-tabs"; form.querySelector(".form-grid").before(tabs); }
      tabs.innerHTML = ""; container.innerHTML = "";
      var editable = (item.edit_fields || []).filter(function (field) { return field.kind !== "protected"; });
      genericUpdates = editable.map(function (field) { return {path:field.path, label:field.label, group:field.group || "General", kind:field.kind, value:field.value == null ? "" : field.value, values:(field.values || []).slice()}; });
      var groups = [];
      genericUpdates.forEach(function (field) { if (!groups.includes(field.group)) groups.push(field.group); });
      if ((item.edit_fields || []).some(function (field) { return field.kind === "protected"; })) groups.push("Protected");
      function activateGroup(group) { all("button", tabs).forEach(function (button) { button.classList.toggle("is-active", button.dataset.genericGroup === group); }); all("[data-generic-group]", container).forEach(function (node) { node.hidden = node.dataset.genericGroup !== group; }); }
      groups.forEach(function (group, index) { var button = document.createElement("button"); button.type = "button"; button.dataset.genericGroup = group; button.textContent = group; if (!index) button.classList.add("is-active"); button.addEventListener("click", function () { activateGroup(group); }); tabs.appendChild(button); });
      genericUpdates.forEach(function (field) {
        var wrapper = document.createElement("div"); wrapper.className = "field full generic-object-field"; wrapper.dataset.genericGroup = field.group; wrapper.hidden = groups.length && field.group !== groups[0];
        var label = document.createElement("label"); label.textContent = field.label; wrapper.appendChild(label);
        var action = field.label.toLocaleLowerCase(); if (["allow", "alert", "block", "continue", "override", "redirect", "none"].includes(action)) { var help = document.createElement("small"); help.textContent = action === "allow" ? "Toestaan zonder URL Filtering-log." : action === "alert" ? "Toestaan en een URL Filtering-log genereren." : "Site Access action: " + action + ". Een categorie kan maar aan één actie tegelijk gekoppeld zijn."; wrapper.appendChild(help); }
        if (field.kind === "boolean" || field.kind === "bool") {
          var scmBool = field.kind === "bool"; var select = document.createElement("select"); (scmBool ? ["true", "false"] : ["yes", "no"]).forEach(function (value) { var option = document.createElement("option"); option.value = value; option.textContent = value === "yes" || value === "true" ? "Yes" : "No"; select.appendChild(option); }); select.value = String(field.value); select.addEventListener("change", function () { field.value = select.value; syncGenericUpdates(); }); wrapper.appendChild(select);
        } else if (field.kind === "members") {
          var tokenInput = document.createElement("div"); tokenInput.className = "token-input"; var chips = document.createElement("div"); chips.className = "token-chip-list";
          var input = document.createElement("input"); input.placeholder = "Zoeken of freeform toevoegen"; if (genericCatalogList) input.setAttribute("list", genericCatalogList.id); var addButton = document.createElement("button"); addButton.type = "button"; addButton.className = "btn"; addButton.textContent = "+"; tokenInput.appendChild(chips); tokenInput.appendChild(input); tokenInput.appendChild(addButton);
          function renderValues() { chips.innerHTML = ""; field.values.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var text = document.createElement("span"); text.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { field.values = field.values.filter(function (candidate) { return candidate !== value; }); syncGenericUpdates(); renderValues(); }); chip.appendChild(text); chip.appendChild(remove); chips.appendChild(chip); }); if (!field.values.length) { var empty = document.createElement("span"); empty.className = "muted"; empty.textContent = "Geen waarden"; chips.appendChild(empty); } }
          function addValue() { var value = input.value.trim(); if (value && !field.values.includes(value)) field.values.push(value); input.value = ""; syncGenericUpdates(); renderValues(); }
          addButton.addEventListener("click", addValue); input.addEventListener("keydown", function (event) { if (event.key === "Enter") { event.preventDefault(); addValue(); } }); wrapper.appendChild(tokenInput); renderValues();
        } else {
          var textValue = typeof field.value === "string" ? field.value : JSON.stringify(field.value, null, 2); var inputField = field.kind === "json" || textValue.length > 160 ? document.createElement("textarea") : document.createElement("input"); inputField.value = textValue; inputField.addEventListener("input", function () { field.value = inputField.value; syncGenericUpdates(); }); wrapper.appendChild(inputField);
        }
        container.appendChild(wrapper);
      });
      if (groups.includes("Protected")) { var protectedNotice = document.createElement("div"); protectedNotice.className = "callout"; protectedNotice.dataset.genericGroup = "Protected"; protectedNotice.hidden = groups[0] !== "Protected"; protectedNotice.innerHTML = "<strong>Beschermde waarden</strong><br>Wachtwoorden, private keys en grote certificaatdata blijven behouden maar worden nooit naar de browser gekopieerd."; container.appendChild(protectedNotice); }
      if (!genericUpdates.length) { var empty = document.createElement("div"); empty.className = "empty-state"; empty.textContent = "Dit object bevat geen configureerbare waarden."; container.appendChild(empty); }
      syncGenericUpdates();
    }
    var logMatchInput = form.querySelector("[data-log-forwarding-match-json]");
    var logMatchList = form.querySelector("[data-log-match-list]");
    var logActionsSupported = Boolean(logMatchInput && logMatchInput.dataset.logActionsSupported === "true");
    var logMatches = [];
    var logDestinationKinds = {send_syslog:"syslog-server-profiles",send_email:"email-server-profiles",send_snmptrap:"snmp-trap-server-profiles",send_http:"http-server-profiles"};
    function normalizedLogAction(item, index) { var action = item || {}; return {name:action.name || "action-" + (index + 1),type:action.type || "tagging",action:action.action || "add-tag",target:action.target || "source-address",registration:action.registration || "localhost",timeout:action.timeout || "",tags:(action.tags || []).slice(),integration_action:action.integration_action || ""}; }
    function normalizedLogMatch(item, index) {
      var match = item || {};
      return {
        name:match.name || "match-" + (index + 1), action_desc:match.action_desc || "",
        log_type:match.log_type || "traffic", filter:match.filter || "",
        send_to_panorama:Boolean(match.send_to_panorama), quarantine:Boolean(match.quarantine),
        send_syslog:(match.send_syslog || []).slice(), send_email:(match.send_email || []).slice(),
        send_snmptrap:(match.send_snmptrap || []).slice(), send_http:(match.send_http || []).slice(),
        actions:(match.actions || []).map(normalizedLogAction)
      };
    }
    function syncLogMatches() { if (logMatchInput) logMatchInput.value = JSON.stringify(logMatches); }
    function logField(labelText, control) { var field = document.createElement("label"); field.className = "field"; var label = document.createElement("span"); label.textContent = labelText; field.appendChild(label); field.appendChild(control); return field; }
    function renderLogDestination(match, fieldName, labelText) {
      var wrapper = document.createElement("div"); wrapper.className = "field full"; var label = document.createElement("label"); label.textContent = labelText; wrapper.appendChild(label);
      var editor = document.createElement("div"); editor.className = "token-input"; var chips = document.createElement("div"); chips.className = "token-chip-list";
      (match[fieldName] || []).forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var text = document.createElement("span"); text.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { match[fieldName] = match[fieldName].filter(function (candidate) { return candidate !== value; }); syncLogMatches(); renderLogMatches(); }); chip.appendChild(text); chip.appendChild(remove); chips.appendChild(chip); });
      if (!(match[fieldName] || []).length) { var empty = document.createElement("span"); empty.className = "muted small"; empty.textContent = "Geen profiel geselecteerd"; chips.appendChild(empty); }
      var choose = document.createElement("button"); choose.type = "button"; choose.className = "btn"; choose.textContent = "Kies"; choose.addEventListener("click", function () { activeLogMatch = match; activeLogField = fieldName; openObjectPicker("log-destination"); });
      editor.appendChild(chips); editor.appendChild(choose); wrapper.appendChild(editor); return wrapper;
    }
    function selectWithValues(values, current, change) { var select = document.createElement("select"); values.forEach(function (value) { var option = document.createElement("option"); option.value = value; option.textContent = value; option.selected = value === current; select.appendChild(option); }); select.addEventListener("change", function () { change(select.value); }); return select; }
    function renderLogActions(match) {
      var section = document.createElement("section"); section.className = "field full log-actions-section";
      var header = document.createElement("div"); header.className = "log-actions-header"; var title = document.createElement("strong"); title.textContent = "Built-in Actions"; var add = document.createElement("button"); add.type = "button"; add.className = "btn btn-small"; add.textContent = "+ Add"; add.addEventListener("click", function () { match.actions.push(normalizedLogAction({}, match.actions.length)); syncLogMatches(); renderLogMatches(); }); header.appendChild(title); header.appendChild(add); section.appendChild(header);
      (match.actions || []).forEach(function (action, actionIndex) {
        var card = document.createElement("div"); card.className = "log-action-card"; var grid = document.createElement("div"); grid.className = "form-grid";
        var name = document.createElement("input"); name.required = true; name.maxLength = 63; name.value = action.name; name.addEventListener("input", function () { action.name = name.value; syncLogMatches(); }); grid.appendChild(logField("Name", name));
        grid.appendChild(logField("Type", selectWithValues(["tagging","integration"], action.type, function (value) { action.type = value; syncLogMatches(); renderLogMatches(); })));
        if (action.type === "integration") {
          var integration = document.createElement("div"); integration.className = "field full"; var integrationLabel = document.createElement("label"); integrationLabel.textContent = "Integration Action"; var integrationEditor = document.createElement("div"); integrationEditor.className = "token-input"; var integrationChips = document.createElement("div"); integrationChips.className = "token-chip-list";
          if (action.integration_action) { var integrationChip = document.createElement("span"); integrationChip.className = "policy-value-chip"; var integrationName = document.createElement("span"); integrationName.textContent = action.integration_action; var integrationRemove = document.createElement("button"); integrationRemove.type = "button"; integrationRemove.textContent = "−"; integrationRemove.addEventListener("click", function () { action.integration_action = ""; syncLogMatches(); renderLogMatches(); }); integrationChip.appendChild(integrationName); integrationChip.appendChild(integrationRemove); integrationChips.appendChild(integrationChip); }
          else { var integrationEmpty = document.createElement("span"); integrationEmpty.className = "muted small"; integrationEmpty.textContent = "Geen bestaande integratieactie geselecteerd"; integrationChips.appendChild(integrationEmpty); }
          var integrationChoose = document.createElement("button"); integrationChoose.type = "button"; integrationChoose.className = "btn"; integrationChoose.textContent = "Kies"; integrationChoose.addEventListener("click", function () { activeLogAction = action; openObjectPicker("log-integration"); }); integrationEditor.appendChild(integrationChips); integrationEditor.appendChild(integrationChoose); integration.appendChild(integrationLabel); integration.appendChild(integrationEditor); grid.appendChild(integration);
        } else {
          grid.appendChild(logField("Action", selectWithValues(["add-tag","remove-tag"], action.action, function (value) { action.action = value; syncLogMatches(); })));
          grid.appendChild(logField("Target", selectWithValues(["source-address","destination-address","xff-address","user"], action.target, function (value) { action.target = value; syncLogMatches(); })));
          grid.appendChild(logField("Registration", selectWithValues(["localhost","panorama","remote"], action.registration, function (value) { action.registration = value; syncLogMatches(); })));
          var timeout = document.createElement("input"); timeout.type = "number"; timeout.min = "0"; timeout.max = "2592000"; timeout.value = action.timeout; timeout.addEventListener("input", function () { action.timeout = timeout.value; syncLogMatches(); }); grid.appendChild(logField("Timeout (sec)", timeout));
          var tags = document.createElement("div"); tags.className = "field full"; var tagsLabel = document.createElement("label"); tagsLabel.textContent = "Tags"; var tagEditor = document.createElement("div"); tagEditor.className = "token-input"; var tagChips = document.createElement("div"); tagChips.className = "token-chip-list";
          action.tags.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var text = document.createElement("span"); text.textContent = value; var removeTag = document.createElement("button"); removeTag.type = "button"; removeTag.textContent = "−"; removeTag.addEventListener("click", function () { action.tags = action.tags.filter(function (candidate) { return candidate !== value; }); syncLogMatches(); renderLogMatches(); }); chip.appendChild(text); chip.appendChild(removeTag); tagChips.appendChild(chip); });
          if (!action.tags.length) { var noTags = document.createElement("span"); noTags.className = "muted small"; noTags.textContent = "Geen tag geselecteerd"; tagChips.appendChild(noTags); }
          var chooseTag = document.createElement("button"); chooseTag.type = "button"; chooseTag.className = "btn"; chooseTag.textContent = "Kies"; chooseTag.addEventListener("click", function () { activeLogAction = action; openObjectPicker("log-action-tags"); }); tagEditor.appendChild(tagChips); tagEditor.appendChild(chooseTag); tags.appendChild(tagsLabel); tags.appendChild(tagEditor); grid.appendChild(tags);
        }
        var removeAction = document.createElement("button"); removeAction.type = "button"; removeAction.className = "btn btn-danger btn-small"; removeAction.textContent = "− Action"; removeAction.addEventListener("click", function () { match.actions.splice(actionIndex, 1); syncLogMatches(); renderLogMatches(); }); var removeWrap = document.createElement("div"); removeWrap.className = "field full log-action-remove"; removeWrap.appendChild(removeAction); grid.appendChild(removeWrap); card.appendChild(grid); section.appendChild(card);
      });
      return section;
    }
    function renderLogMatches() {
      if (!logMatchList) return; logMatchList.innerHTML = "";
      logMatches.forEach(function (match, index) {
        var card = document.createElement("article"); card.className = "log-match-card"; var header = document.createElement("div"); header.className = "log-match-header"; var title = document.createElement("strong"); title.textContent = match.name || "Nieuwe match"; var remove = document.createElement("button"); remove.type = "button"; remove.className = "btn btn-danger btn-small"; remove.textContent = "−"; remove.title = "Match-list entry verwijderen"; remove.addEventListener("click", function () { logMatches.splice(index, 1); syncLogMatches(); renderLogMatches(); }); header.appendChild(title); header.appendChild(remove); card.appendChild(header);
        var grid = document.createElement("div"); grid.className = "form-grid log-match-grid";
        var name = document.createElement("input"); name.required = true; name.maxLength = 63; name.value = match.name; name.addEventListener("input", function () { match.name = name.value; title.textContent = name.value || "Nieuwe match"; syncLogMatches(); }); grid.appendChild(logField("Name", name));
        var logType = document.createElement("select"); ["traffic","threat","wildfire","url","data","gtp","sctp","tunnel","auth","decryption","dns-security"].forEach(function (value) { var option = document.createElement("option"); option.value = value; option.textContent = value; option.selected = value === match.log_type; logType.appendChild(option); }); logType.addEventListener("change", function () { match.log_type = logType.value; syncLogMatches(); }); grid.appendChild(logField("Log Type", logType));
        var description = document.createElement("input"); description.maxLength = 255; description.value = match.action_desc; description.addEventListener("input", function () { match.action_desc = description.value; syncLogMatches(); }); var descriptionField = logField("Description", description); descriptionField.classList.add("full"); grid.appendChild(descriptionField);
        var filter = document.createElement("textarea"); filter.rows = 2; filter.value = match.filter; filter.placeholder = "Leeg = alle logs van dit type"; filter.addEventListener("input", function () { match.filter = filter.value; syncLogMatches(); }); var filterField = logField("Filter", filter); filterField.classList.add("full"); grid.appendChild(filterField);
        var panorama = document.createElement("label"); panorama.className = "checkbox"; var panoramaInput = document.createElement("input"); panoramaInput.type = "checkbox"; panoramaInput.checked = match.send_to_panorama; panoramaInput.addEventListener("change", function () { match.send_to_panorama = panoramaInput.checked; syncLogMatches(); }); panorama.appendChild(panoramaInput); panorama.append(" Panorama / Strata Logging Service"); grid.appendChild(panorama);
        var quarantine = document.createElement("label"); quarantine.className = "checkbox"; var quarantineInput = document.createElement("input"); quarantineInput.type = "checkbox"; quarantineInput.checked = match.quarantine; quarantineInput.addEventListener("change", function () { match.quarantine = quarantineInput.checked; syncLogMatches(); }); quarantine.appendChild(quarantineInput); quarantine.append(" Quarantine"); grid.appendChild(quarantine);
        grid.appendChild(renderLogDestination(match,"send_syslog","Syslog")); grid.appendChild(renderLogDestination(match,"send_email","Email")); grid.appendChild(renderLogDestination(match,"send_snmptrap","SNMP Trap")); grid.appendChild(renderLogDestination(match,"send_http","HTTP")); if (logActionsSupported) grid.appendChild(renderLogActions(match));
        card.appendChild(grid); logMatchList.appendChild(card);
      });
      if (!logMatches.length) { var empty = document.createElement("div"); empty.className = "empty-state"; empty.innerHTML = "<strong>Geen match-list entries</strong>Voeg minstens één log type, filter en destination toe."; logMatchList.appendChild(empty); }
      syncLogMatches();
    }
    function setLogMatches(values) { logMatches = (Array.isArray(values) ? values : []).map(normalizedLogMatch); if (!logMatches.length) logMatches.push(normalizedLogMatch({}, 0)); renderLogMatches(); }
    var addLogMatch = form.querySelector("[data-log-match-add]"); if (addLogMatch) addLogMatch.addEventListener("click", function () { logMatches.push(normalizedLogMatch({}, logMatches.length)); renderLogMatches(); });
    function openEditor(item, createMode) {
      form.reset(); form.querySelector("[data-object-id]").value = !createMode && item && item.id ? item.id : "";
      dialog.querySelector("[data-object-dialog-title]").textContent = (createMode ? "Add " : "Edit ") + document.querySelector(".object-list h2").textContent;
      setMembers([]); setTags([]); setDynamicFilter(""); setLogMatches(item && item.match_list ? item.match_list : []); zoneReferenceFields.forEach(function (field) { setZoneReference(field.dataset.zoneReferenceField, []); });
      var zoneConfig = form.querySelector("[data-zone-current-config]");
      if (!zoneConfig && form.querySelector('[data-object-field="zone_type"]')) { zoneConfig = document.createElement("details"); zoneConfig.className = "zone-current-config field full"; zoneConfig.dataset.zoneCurrentConfig = ""; var summary = document.createElement("summary"); summary.textContent = "Volledige huidige zoneconfig"; var pre = document.createElement("pre"); pre.className = "mono"; zoneConfig.appendChild(summary); zoneConfig.appendChild(pre); form.querySelector(".form-grid").appendChild(zoneConfig); }
      if (zoneConfig) { zoneConfig.hidden = !(item && item.network); if (item && item.network) { var visibleConfig = {}; Object.keys(item).sort().forEach(function (key) { if (!["_xml", "_raw"].includes(key)) visibleConfig[key] = item[key]; }); zoneConfig.querySelector("pre").textContent = JSON.stringify(visibleConfig, null, 2); } }
      if (item) {
        setField("name", createMode ? "" : item.name); setField("description", item.description); setField("comments", item.comments); setTags(item.tag);
        if (genericEditor || item.generic) { loadGenericUrlCatalog(); var descriptionField = form.querySelector('[data-object-field="description"]'); if (descriptionField) descriptionField.closest(".field").hidden = true; renderGenericFields(item); }
        ["ip_netmask", "ip_range", "ip_wildcard", "fqdn"].some(function (kind) { if (item[kind]) { setField("value_type", kind); setField("value", item[kind]); return true; } return false; });
        if (item.dynamic) { if (groupType) groupType.value = "dynamic"; setDynamicFilter(typeof item.dynamic === "object" ? item.dynamic.filter : item.dynamic); } else { if (groupType) groupType.value = "static"; setMembers(item.static); setDynamicFilter(""); }
        if (item.members) setMembers(item.members);
        if (item.protocol) { var protocolName = Object.keys(item.protocol)[0]; var details = item.protocol[protocolName] || {}; setField("protocol_name", protocolName); ["port", "source_port", "timeout", "halfclose_timeout", "timewait_timeout"].forEach(function (key) { setField(key, details[key]); }); if (override) override.checked = Boolean(details.override || details.timeout || details.halfclose_timeout || details.timewait_timeout); }
        if (item.network) { var zoneType = Object.keys(item.network)[0] || "layer3"; var zoneInterfaces = item.network[zoneType] || []; setField("zone_type", zoneType.replace("-", "_")); setZoneReference("interfaces", Array.isArray(zoneInterfaces) ? zoneInterfaces : zoneInterfaces.member || []); }
        var userId = form.querySelector('[data-object-field="enable_user_identification"]'); if (userId) userId.checked = item.enable_user_identification === true || item.enable_user_identification === "yes";
        setZoneReference("zone_protection_profile", item.zone_protection_profile); setZoneReference("log_setting", item.log_setting);
        setField("color", item.color);
      }
      var enhancedLogging = form.querySelector('[data-object-field="enhanced_application_logging"]'); if (enhancedLogging) enhancedLogging.checked = Boolean(item && item.enhanced_application_logging);
      updateGroupType(); updateTimeouts(); dialog.showModal();
    }
    var add = document.querySelector("[data-object-add]");
    var createTemplateNode = document.querySelector("[data-object-create-template]");
    var createTemplate = null;
    if (createTemplateNode) { try { createTemplate = JSON.parse(createTemplateNode.textContent || "null"); } catch (_) { createTemplate = null; } }
    if (!add && genericEditor) {
      var actionCluster = deleteButton && deleteButton.closest(".object-actionbar") && deleteButton.closest(".object-actionbar").querySelector(".cluster");
      if (actionCluster) { add = document.createElement("button"); add.type = "button"; add.className = "btn btn-primary"; add.dataset.objectAdd = ""; add.textContent = "+ Add"; actionCluster.insertBefore(add, deleteButton); }
    }
    if (add) add.addEventListener("click", function () {
      if (genericEditor && !createTemplate) { window.alert("Voor dit objecttype is geen veilig create-schema beschikbaar."); return; }
      openEditor(genericEditor ? createTemplate : null, true);
    });
    if (add && new URLSearchParams(window.location.search).get("add_object") === "1") {
      if (!genericEditor || createTemplate) openEditor(genericEditor ? createTemplate : null, true);
    }
    rows.forEach(function (row) { var button = row.querySelector("[data-object-edit]"); if (!button) return; var item = JSON.parse(row.dataset.object); if (item.network) { var zoneType = Object.keys(item.network)[0] || "onbekend"; var zoneValue = item.network[zoneType] || []; var zoneInterfaces = Array.isArray(zoneValue) ? zoneValue : zoneValue.member || []; var valueCell = row.querySelector("td.mono"); if (valueCell) valueCell.textContent = zoneType.replace("_", "-") + (zoneInterfaces.length ? " · " + zoneInterfaces.join(", ") : " · geen interfaces") + " · User-ID " + ((item.enable_user_identification === true || item.enable_user_identification === "yes") ? "aan" : "uit"); } button.addEventListener("click", function () { openEditor(item, false); }); row.addEventListener("click", function (event) { if (!event.target.closest("input,button,a")) openEditor(item, false); }); });
    var objectList = document.querySelector(".object-list[data-edit-object]");
    var requestedObject = objectList ? objectList.dataset.editObject : "";
    if (requestedObject) {
      var requestedRow = rows.find(function (row) { var item = JSON.parse(row.dataset.object); return item.editable && item.name === requestedObject; });
      if (requestedRow) openEditor(JSON.parse(requestedRow.dataset.object), false);
    }
    var cancel = dialog.querySelector("[data-object-cancel]"); if (cancel) cancel.addEventListener("click", function () { dialog.close(); });
    form.addEventListener("submit", function () { addFreeformTag(); commitDynamicEntry(); syncGenericUpdates(); syncLogMatches(); });
    var pickerPanel = dialog.querySelector("[data-member-picker-panel]"); var catalogNode = dialog.querySelector("[data-object-catalog]"); var catalog = catalogNode ? JSON.parse(catalogNode.textContent || "[]") : []; var pickerMode = "members"; var objectPickerSelections = new Set(); var activeLogMatch = null; var activeLogField = ""; var activeLogAction = null; var activeZoneReference = null;
    var objectApplicationCatalog = dialog.querySelector("[data-object-application-catalog]"); var objectApplicationsLoaded = false;
    function loadObjectApplications() { if (!objectApplicationCatalog || objectApplicationsLoaded) return; objectApplicationsLoaded = true; fetch(objectApplicationCatalog.dataset.objectApplicationCatalog, {headers:{"Accept":"application/json"}}).then(function (response) { if (!response.ok) throw new Error("HTTP " + response.status); return response.json(); }).then(function (data) { var known = new Set(catalog.map(function (item) { return item.kind + "\u0000" + item.name; })); (data.items || []).forEach(function (item) { var key = "applications\u0000" + item.name; if (!known.has(key)) { known.add(key); catalog.push({name:item.name,kind:"applications"}); } }); if (pickerMode === "members" && pickerPanel && !pickerPanel.hidden) renderCatalog((pickerPanel.querySelector("[data-member-filter]").value || "").toLocaleLowerCase()); if (!data.ready && data.refreshing) { objectApplicationsLoaded = false; setTimeout(loadObjectApplications, 3000); } }).catch(function () { objectApplicationsLoaded = false; }); }
    function updateObjectPickerCount() { var count = pickerPanel && pickerPanel.querySelector("[data-object-picker-selected-count]"); if (count) count.textContent = objectPickerSelections.size; }
    function compatibleCatalogItem(item) { if (pickerMode === "dynamic" || pickerMode === "tags" || pickerMode === "log-action-tags") return item.kind === "tags"; if (pickerMode === "log-destination") return item.kind === logDestinationKinds[activeLogField]; if (pickerMode === "log-integration") return item.kind === "log-integration-actions"; if (pickerMode === "zone-reference") return Boolean(activeZoneReference && item.kind === activeZoneReference.dataset.zoneReferenceKind); return item.kind !== "tags"; }
    function dynamicTokenName(value) { var clean = (value || "").trim(); var first = clean.charAt(0); if (clean.length > 1 && clean.charAt(clean.length - 1) === first && (first.charCodeAt(0) === 39 || first.charCodeAt(0) === 34)) clean = clean.slice(1, -1); return clean; }
    function objectValueAlreadyAssigned(name) { if (pickerMode === "members") return memberSet.has(name); if (pickerMode === "tags") return tagSet.has(name); if (pickerMode === "dynamic") return dynamicTokens.some(function (token) { return dynamicTokenName(token) === name; }); if (pickerMode === "log-destination") return Boolean(activeLogMatch && (activeLogMatch[activeLogField] || []).includes(name)); if (pickerMode === "log-action-tags") return Boolean(activeLogAction && activeLogAction.tags.includes(name)); if (pickerMode === "log-integration") return Boolean(activeLogAction && activeLogAction.integration_action === name); if (pickerMode === "zone-reference") return Boolean(activeZoneReference && zoneReferenceValues(activeZoneReference).has(name)); return false; }
    function renderCatalog(query) { if (!pickerPanel) return; var results = pickerPanel.querySelector("[data-member-results]"); results.innerHTML = ""; var ownName = form.querySelector('[name="name"]').value; var matches = catalog.filter(function (item) { return item.name !== ownName && compatibleCatalogItem(item) && !objectValueAlreadyAssigned(item.name) && (!query || item.name.toLocaleLowerCase().includes(query)); }); matches.forEach(function (item) { var row = document.createElement("div"); row.className = "member-result" + (objectPickerSelections.has(item.name) ? " is-selected" : ""); var copy = document.createElement("div"); var strong = document.createElement("strong"); strong.textContent = item.name; var small = document.createElement("small"); small.textContent = item.kind; copy.appendChild(strong); copy.appendChild(small); var button = document.createElement("button"); button.className = "btn btn-small"; button.type = "button"; button.textContent = objectPickerSelections.has(item.name) ? "Geselecteerd" : "Selecteer"; function toggleSelection() { if (objectPickerSelections.has(item.name)) objectPickerSelections.delete(item.name); else { if (pickerMode === "log-integration" || (pickerMode === "zone-reference" && activeZoneReference && activeZoneReference.dataset.zoneReferenceCardinality === "one")) objectPickerSelections.clear(); objectPickerSelections.add(item.name); } updateObjectPickerCount(); renderCatalog(query); } button.addEventListener("click", function (event) { event.stopPropagation(); toggleSelection(); }); row.addEventListener("click", toggleSelection); row.appendChild(copy); row.appendChild(button); results.appendChild(row); }); if (!matches.length) { var empty = document.createElement("div"); empty.className = "muted member-result"; empty.textContent = catalog.length ? "Geen extra waarden gevonden" : "Catalogus wordt bijgewerkt; vernieuw deze pagina over enkele ogenblikken."; results.appendChild(empty); } updateObjectPickerCount(); }
    function updateObjectCreateLink(mode) { var row = pickerPanel.querySelector("[data-object-picker-create-row]"); var link = pickerPanel.querySelector("[data-object-picker-create]"); if (!row || !link) return; var kind = (mode === "tags" || mode === "dynamic" || mode === "log-action-tags") ? "tags" : mode === "members" ? ({"address-groups":"addresses","service-groups":"services"}[currentObjectType] || "") : mode === "zone-reference" && activeZoneReference ? activeZoneReference.dataset.zoneReferenceKind : ""; if (!kind) { row.hidden = true; return; } var action = form.getAttribute("action") || ""; var workspaceMatch = action.match(/\/config-workspaces\/(\d+)\//); var profileMatch = action.match(/\/objects\/(\d+)\//); var scope = form.querySelector('[name="scope"]'); if (workspaceMatch) link.href = "/config-workspaces/" + workspaceMatch[1] + "/edit?scope=" + encodeURIComponent(scope ? scope.value : "") + "&workspace_view=objects&object_type=" + encodeURIComponent(kind) + "&add_object=1"; else if (profileMatch && kind === "interfaces") link.href = "/?policy_profile=" + profileMatch[1] + "&policy_view=network&config_section=interfaces#policy-management"; else if (profileMatch && kind === "zone-protection-profiles") link.href = "/?policy_profile=" + profileMatch[1] + "&policy_view=network&config_section=network-profiles#policy-management"; else if (profileMatch) link.href = "/?policy_profile=" + profileMatch[1] + "&policy_view=objects&object_type=" + encodeURIComponent(kind) + "&add_object=1#policy-management"; else { row.hidden = true; return; } row.hidden = false; }
    function openObjectPicker(mode) { if (!pickerPanel) return; pickerMode = mode; objectPickerSelections.clear(); pickerPanel.hidden = false; var title = pickerPanel.querySelector("[data-object-picker-title]"); if (title) title.textContent = mode === "log-destination" ? "Bestaande serverprofielen kiezen" : mode === "log-action-tags" ? "Bestaande tags kiezen" : mode === "log-integration" ? "Bestaande integratieactie kiezen" : mode === "zone-reference" && activeZoneReference ? "Bestaande " + activeZoneReference.dataset.zoneReferenceKind + " kiezen" : "Bestaande waarden kiezen"; var filter = pickerPanel.querySelector("[data-member-filter]"); filter.value = ""; updateObjectCreateLink(mode); renderCatalog(""); if (mode === "members") loadObjectApplications(); filter.focus(); }
    var pickerOpen = dialog.querySelector("[data-member-picker-open]"); if (pickerOpen) pickerOpen.addEventListener("click", function () { openObjectPicker("members"); });
    var tagPickerOpen = dialog.querySelector("[data-tag-picker-open]"); if (tagPickerOpen) tagPickerOpen.addEventListener("click", function () { openObjectPicker("tags"); });
    var tagEntry = dialog.querySelector("[data-object-tag-entry]"); var tagAdd = dialog.querySelector("[data-object-tag-add]");
    function addFreeformTag() { if (!tagEntry || tagEntry.readOnly) return; var values = parseTagTokens(tagEntry.value); if (!values.length) return; values.forEach(function (value) { tagSet.add(value); }); if (tagInput) tagInput.value = Array.from(tagSet).join(","); tagEntry.value = ""; renderTags(); }
    if (tagEntry) { tagEntry.addEventListener("focus", function () { openObjectPicker("tags"); }); tagEntry.addEventListener("keydown", function (event) { if (!tagEntry.readOnly && (event.key === "Enter" || event.key === "," || (event.key === " " && !tagQuoteOpen(tagEntry.value)))) { event.preventDefault(); addFreeformTag(); } }); }
    if (tagAdd) tagAdd.addEventListener("click", addFreeformTag);
    if (dynamicEntry && pickerPanel) dynamicEntry.addEventListener("focus", function () { openObjectPicker("dynamic"); });
    zoneReferenceFields.forEach(function (field) { var entry = field.querySelector("[data-zone-reference-entry]"); var choose = field.querySelector("[data-zone-reference-open]"); function open() { activeZoneReference = field; openObjectPicker("zone-reference"); } if (entry) entry.addEventListener("focus", open); if (choose) choose.addEventListener("click", open); });
    var addObjectPickerSelected = dialog.querySelector("[data-object-picker-add-selected]"); if (addObjectPickerSelected) addObjectPickerSelected.addEventListener("click", function () { objectPickerSelections.forEach(function (name) { if (pickerMode === "dynamic") { var quoted = "'" + name.replace(/'/g, "\\'") + "'"; if (!dynamicTokens.includes(quoted)) dynamicTokens.push(quoted); } else if (pickerMode === "tags") { tagSet.add(name); } else if (pickerMode === "log-destination" && activeLogMatch) { if (!activeLogMatch[activeLogField].includes(name)) activeLogMatch[activeLogField].push(name); } else if (pickerMode === "log-action-tags" && activeLogAction) { if (!activeLogAction.tags.includes(name)) activeLogAction.tags.push(name); } else if (pickerMode === "log-integration" && activeLogAction) { activeLogAction.integration_action = name; } else if (pickerMode === "zone-reference" && activeZoneReference) { var zoneValues = zoneReferenceValues(activeZoneReference); if (activeZoneReference.dataset.zoneReferenceCardinality === "one") zoneValues.clear(); zoneValues.add(name); } else { memberSet.add(name); } }); if (pickerMode === "dynamic") syncDynamicFilter(); else if (pickerMode === "tags") { if (tagInput) tagInput.value = Array.from(tagSet).join(","); renderTags(); } else if (["log-destination","log-action-tags","log-integration"].includes(pickerMode)) { syncLogMatches(); renderLogMatches(); } else if (pickerMode === "zone-reference" && activeZoneReference) { renderZoneReference(activeZoneReference); } else { if (memberInput) memberInput.value = Array.from(memberSet).join(","); renderMembers(); } objectPickerSelections.clear(); updateObjectPickerCount(); pickerPanel.hidden = true; });
    var pickerClose = dialog.querySelector("[data-member-picker-close]"); if (pickerClose) pickerClose.addEventListener("click", function () { pickerPanel.hidden = true; });
    var memberFilter = dialog.querySelector("[data-member-filter]"); if (memberFilter) memberFilter.addEventListener("input", function () { renderCatalog(memberFilter.value.toLocaleLowerCase().trim()); });
    updateCount(); updateGroupType(); updateTimeouts();
  }

  function setupOfflinePolicyTabs() {
    var offlineDialog = document.querySelector("[data-offline-policy-dialog]");
    if (offlineDialog && !offlineDialog.open) offlineDialog.showModal();
    var tabs = all("[data-offline-policy-tab]");
    var panels = all("[data-offline-policy-panel]");
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        tabs.forEach(function (item) { item.classList.toggle("is-active", item === tab); });
        panels.forEach(function (panel) {
          panel.classList.toggle("is-active", panel.dataset.offlinePolicyPanel === tab.dataset.offlinePolicyTab);
        });
      });
    });
    var fields = all("[data-offline-policy-field]");
    var bulkDialog = document.querySelector("[data-policy-bulk-dialog]");
    var bulkFields = bulkDialog ? all("[data-bulk-field],[data-bulk-scalar-field]", bulkDialog) : [];
    fields.forEach(function (field) {
      var hidden = field.querySelector("[data-offline-policy-input]");
      var entry = field.querySelector("[data-offline-policy-entry]");
      var values = new Set((hidden.value || "").split(",").map(function (value) { return value.trim(); }).filter(Boolean));
      function render() {
        var container = field.querySelector("[data-offline-policy-values]"); container.innerHTML = "";
        values.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { values.delete(value); hidden.value = Array.from(values).join(","); render(); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); });
        if (!values.size) { var empty = document.createElement("span"); empty.className = "muted"; empty.textContent = "Geen waarden"; container.appendChild(empty); }
      }
      function addValue(value, exact) { var additions = exact ? [(value || "").trim()].filter(Boolean) : field.dataset.offlinePolicyField === "tag" ? parseTagTokens(value) : [(value || "").trim()].filter(Boolean); if (!additions.length) return; if (field.dataset.offlineCardinality === "one") values.clear(); else { var exclusiveValues = {from:["any"],to:["any"],source:["any"],destination:["any"],source_user:["any"],source_hip:["any"],destination_user:["any"],destination_hip:["any"],application:["any"],service:["any","application-default"],category:["any"]}[field.dataset.offlinePolicyField] || []; var hasSpecific = additions.some(function (item) { return exclusiveValues.indexOf(item) < 0; }); var hasExclusive = additions.some(function (item) { return exclusiveValues.indexOf(item) >= 0; }); if (hasSpecific) exclusiveValues.forEach(function (item) { values.delete(item); }); else if (hasExclusive) values.clear(); } additions.forEach(function (item) { values.add(item); }); hidden.value = Array.from(values).join(","); entry.value = ""; render(); }
      field._offlineAddValue = addValue;
      field._offlineValues = values;
      field.querySelector("[data-offline-policy-add]").addEventListener("click", function () { if (!entry.readOnly) addValue(entry.value, false); });
      entry.addEventListener("keydown", function (event) { var tagDelimiter = field.dataset.offlinePolicyField === "tag" && (event.key === "," || (event.key === " " && !tagQuoteOpen(entry.value))); if (!entry.readOnly && (event.key === "Enter" || tagDelimiter)) { event.preventDefault(); addValue(entry.value, false); } });
      render();
    });
    var offlineForm = offlineDialog && offlineDialog.querySelector("form"); if (offlineForm) offlineForm.addEventListener("submit", function () { fields.forEach(function (field) { var entry = field.querySelector("[data-offline-policy-entry]"); if (entry && entry.value.trim()) field._offlineAddValue(entry.value); }); });
    var picker = document.querySelector("[data-offline-policy-picker]");
    var catalogNode = document.querySelector("[data-offline-policy-catalog]");
    if (picker && catalogNode && (fields.length || bulkFields.length)) {
      var catalog = JSON.parse(catalogNode.textContent || "[]"); var activeField = null; var selected = new Set(); var currentQuery = "";
      var applicationState = document.querySelector("[data-workspace-application-catalog]"); var applicationPolls = 0;
      function updateSelectedCount() { var count = picker.querySelector("[data-policy-picker-selected-count]"); if (count) count.textContent = selected.size; }
      function renderPicker(query) {
        currentQuery = query;
        var results = picker.querySelector("[data-offline-policy-picker-results]"); results.innerHTML = "";
        var entry = activeField && activeField.querySelector("[data-offline-policy-entry],[data-bulk-entry],[data-bulk-scalar-entry]");
        var kinds = entry ? (entry.dataset.offlinePolicyKinds || entry.dataset.pickerKinds || "").split(/\s+/).filter(Boolean) : [];
        var candidates = catalog.filter(function (item) { return kinds.includes(item.kind); });
        var currentValues = activeField && (activeField._offlineValues || activeField._currentValues);
        if (kinds.includes("current") && currentValues) { var seen = new Set(candidates.map(function (item) { return item.name; })); currentValues.forEach(function (name) { if (!seen.has(name)) { seen.add(name); candidates.push({name:name,kind:"huidige configuratie"}); } }); }
        var isBulkField = Boolean(activeField && (activeField.hasAttribute("data-bulk-field") || activeField.hasAttribute("data-bulk-scalar-field")));
        candidates.filter(function (item) { return (!isBulkField && currentValues && currentValues.has && currentValues.has(item.name)) ? false : (!query || item.name.toLocaleLowerCase().includes(query)); }).forEach(function (item) { var row = document.createElement("div"); row.className = "member-result" + (selected.has(item.name) ? " is-selected" : ""); var copy = document.createElement("div"); var strong = document.createElement("strong"); strong.textContent = item.name; var small = document.createElement("small"); small.textContent = item.kind; copy.appendChild(strong); copy.appendChild(small); var button = document.createElement("button"); button.type = "button"; button.className = "btn btn-small"; button.textContent = selected.has(item.name) ? "Geselecteerd" : "Selecteer"; function toggleSelection() { if (selected.has(item.name)) selected.delete(item.name); else { if (activeField && (activeField.dataset.offlineCardinality === "one" || activeField.hasAttribute("data-bulk-scalar-field"))) selected.clear(); selected.add(item.name); } updateSelectedCount(); renderPicker(query); } button.addEventListener("click", function (event) { event.stopPropagation(); toggleSelection(); }); row.addEventListener("click", toggleSelection); row.appendChild(copy); row.appendChild(button); results.appendChild(row); });
        if (!results.children.length) { var empty = document.createElement("div"); empty.className = "muted member-result"; empty.textContent = "Geen bestaande compatibele waarde gevonden."; results.appendChild(empty); }
        updateSelectedCount();
      }
      function loadWorkspaceApplications() { if (!applicationState) return; var status = picker.querySelector("[data-policy-picker-status]"); if (status) status.textContent = "Application database wordt geladen…"; fetch(applicationState.dataset.workspaceApplicationCatalog, {headers:{"Accept":"application/json"}}).then(function (response) { if (!response.ok) throw new Error("HTTP " + response.status); return response.json(); }).then(function (data) { var existing = new Set(catalog.filter(function (item) { return item.kind === "applications"; }).map(function (item) { return item.name; })); (data.items || []).forEach(function (item) { if (!existing.has(item.name)) { existing.add(item.name); catalog.push(item); } }); if (status) status.textContent = data.error ? "Applicatiecatalogus kon niet worden bijgewerkt." : data.ready ? data.items.length + " applicaties beschikbaar." : data.refreshing ? "Application database wordt geladen…" : "Geen application database beschikbaar."; var activeEntry = activeField && activeField.querySelector("[data-offline-policy-entry],[data-bulk-entry],[data-bulk-scalar-entry]"); if (activeEntry && (activeEntry.dataset.offlinePolicyKinds || activeEntry.dataset.pickerKinds || "").includes("applications")) renderPicker(currentQuery); if (!data.ready && data.refreshing && applicationPolls < 40) { applicationPolls += 1; setTimeout(loadWorkspaceApplications, 3000); } }).catch(function () { if (status) status.textContent = "Applicatiecatalogus kon niet worden bijgewerkt."; }); }
      function updateOfflineCreateLink(field) {
        var row = picker.querySelector("[data-policy-picker-create-row]"); var link = picker.querySelector("[data-policy-picker-create]");
        var fieldName = field.dataset.offlinePolicyField || field.dataset.bulkField || field.dataset.bulkScalarField || "";
        var kindByField = {from:"zones",to:"zones",source:"addresses",destination:"addresses",application:"application-groups",service:"services",tag:"tags",category:"custom-url-categories",log_setting:"log-forwarding",profile_group:"security-profile-groups",source_translation_address:"addresses",destination_translation_address:"addresses"};
        var kind = kindByField[fieldName]; var ownerForm = field.closest("form") || offlineForm; var action = ownerForm ? ownerForm.getAttribute("action") || "" : ""; var workspaceMatch = action.match(/\/config-workspaces\/(\d+)\//); var scope = ownerForm && ownerForm.querySelector('[name="scope"]');
        if (!row || !link || !kind || !workspaceMatch) { if (row) row.hidden = true; return; }
        link.href = "/config-workspaces/" + workspaceMatch[1] + "/edit?scope=" + encodeURIComponent(scope ? scope.value : "") + "&workspace_view=" + (kind === "zones" ? "network&config_section=zones" : "objects&object_type=" + encodeURIComponent(kind) + "&add_object=1"); row.hidden = false;
      }
      function openOfflinePicker(field) { var entry = field.querySelector("[data-offline-policy-entry],[data-bulk-entry],[data-bulk-scalar-entry]"); activeField = field; selected.clear(); var ownerDialog = field.closest("dialog"); if (ownerDialog && picker.parentElement !== ownerDialog) ownerDialog.appendChild(picker); picker.hidden = false; var status = picker.querySelector("[data-policy-picker-status]"); if (status) status.textContent = ""; var filter = picker.querySelector("[data-offline-policy-picker-filter]"); filter.value = ""; updateOfflineCreateLink(field); renderPicker(""); window.requestAnimationFrame(function () { filter.focus(); }); if ((entry.dataset.offlinePolicyKinds || entry.dataset.pickerKinds || "").includes("applications")) { applicationPolls = 0; loadWorkspaceApplications(); } }
      function bindOfflinePickerField(field) { var entry = field.querySelector("[data-offline-policy-entry],[data-bulk-entry],[data-bulk-scalar-entry]"); if (!entry) return; if (entry.readOnly) entry.addEventListener("focus", function () { openOfflinePicker(field); }); var choose = field.querySelector("[data-offline-policy-add],[data-bulk-add-button],[data-bulk-scalar-choose]"); if (choose && entry.readOnly) choose.addEventListener("click", function () { openOfflinePicker(field); }); var openPicker = field.querySelector("[data-offline-policy-open-picker],[data-bulk-picker-button]"); if (openPicker) openPicker.addEventListener("click", function () { openOfflinePicker(field); }); }
      fields.forEach(bindOfflinePickerField); bulkFields.forEach(bindOfflinePickerField);
      picker.querySelector("[data-offline-policy-picker-filter]").addEventListener("input", function (event) { renderPicker(event.target.value.toLocaleLowerCase().trim()); });
      picker.querySelector("[data-offline-policy-picker-close]").addEventListener("click", function () { picker.hidden = true; });
      var addSelected = picker.querySelector("[data-policy-picker-add-selected]"); if (addSelected) addSelected.addEventListener("click", function () { if (!activeField) return; selected.forEach(function (name) { if (activeField._offlineAddValue) activeField._offlineAddValue(name, true); else if (activeField._addBulkValue) activeField._addBulkValue(name); else if (activeField._addScalarValue) activeField._addScalarValue(name); }); selected.clear(); updateSelectedCount(); picker.hidden = true; });
    }
  }

  function setupConfigPullProgress() {
    all("form[data-config-pull]").forEach(function (form) {
      form.addEventListener("submit", function () {
        var button = form.querySelector('button[type="submit"]');
        var status = form.querySelector("[data-config-pull-status]");
        var progress = form.querySelector("[data-config-pull-progress]");
        if (button) { button.disabled = true; button.textContent = "Configuratie ophalen…"; }
        if (status) { status.hidden = false; status.textContent = "Verbinden en volledige candidateconfiguratie ophalen…"; }
        if (progress) progress.hidden = false;
      });
    });
  }

  function setupIncrementalPushControls() {
    all("form[data-incremental-push]").forEach(function (form) {
      var button = form.querySelector('button[type="submit"]');
      var commitOption = form.querySelector("[data-commit-after-push]");
      var selectAll = form.querySelector("[data-push-select-all]");
      var familyChecks = all("[data-push-family]", form);
      function updateSelectionState() {
        if (!selectAll) return;
        var selectedCount = familyChecks.filter(function (checkbox) { return checkbox.checked; }).length;
        selectAll.checked = familyChecks.length > 0 && selectedCount === familyChecks.length;
        selectAll.indeterminate = selectedCount > 0 && selectedCount < familyChecks.length;
      }
      if (selectAll) selectAll.addEventListener("change", function () {
        familyChecks.forEach(function (checkbox) { checkbox.checked = selectAll.checked; });
        updateSelectionState();
      });
      familyChecks.forEach(function (checkbox) {
        checkbox.addEventListener("change", updateSelectionState);
      });
      updateSelectionState();
      function updateButtonLabel() {
        if (button) button.textContent = commitOption && commitOption.checked
          ? "Geselecteerde families schrijven en committen"
          : "Geselecteerde families naar candidate schrijven";
      }
      if (commitOption) commitOption.addEventListener("change", updateButtonLabel);
      form.addEventListener("submit", function () {
        var progress = form.querySelector("[data-incremental-push-progress]");
        if (button) { button.disabled = true; button.textContent = "Push bezig…"; }
        if (progress) progress.hidden = false;
      });
    });
  }

  function setupCommitStatusPolling() {
    all("[data-config-workspace-commit-status]").forEach(function (root) {
      var label = root.querySelector("[data-commit-status-label]");
      var progress = root.querySelector("[data-commit-progress]");
      var error = root.querySelector("[data-commit-status-error]");
      var cadence = root.querySelector("[data-commit-status-cadence]");
      var details = root.querySelector("[data-commit-status-details]");
      var refresh = root.querySelector("[data-commit-status-refresh]");
      var statusUrl = root.dataset.statusUrl;
      var timer = null;
      var terminal = root.dataset.terminal === "true";
      if (!statusUrl || terminal) return;

      function schedule(seconds) {
        if (timer) window.clearTimeout(timer);
        var delay = Math.max(1, Number(seconds) || 60);
        if (cadence) cadence.textContent = "Volgende targetcontrole over " + Math.ceil(delay) + " seconden.";
        timer = window.setTimeout(check, delay * 1000);
      }

      function renderStatus(data) {
        if (label && data.label) label.textContent = data.label;
        if (progress) progress.textContent = data.progress === null || data.progress === undefined ? "" : " · " + data.progress + "%";
        if (error) error.textContent = data.error || "";
        if (details) {
          details.replaceChildren();
          (Array.isArray(data.details) ? data.details : []).forEach(function (item) {
            var entry = document.createElement("li");
            entry.textContent = String(item);
            details.appendChild(entry);
          });
        }
        terminal = data.terminal === true;
        root.dataset.terminal = terminal ? "true" : "false";
        if (terminal) {
          if (timer) window.clearTimeout(timer);
          if (cadence) cadence.textContent = "Commitstatus is definitief.";
        } else {
          schedule(data.retry_after || 60);
        }
      }

      function check() {
        if (terminal) return;
        if (refresh) refresh.disabled = true;
        fetch(statusUrl, { credentials: "same-origin", cache: "no-store" })
          .then(function (response) {
            if (!response.ok) throw new Error("Status kon niet worden opgehaald.");
            return response.json();
          })
          .then(renderStatus)
          .catch(function () {
            if (error) error.textContent = "Statuscontrole mislukt. Er volgt over maximaal één minuut een nieuwe poging.";
            schedule(60);
          })
          .finally(function () { if (refresh) refresh.disabled = false; });
      }

      if (refresh) refresh.addEventListener("click", function () { check(); });
      check();
    });
  }

  function setupWorkspaceConfigurationEditor() {
    var dialog = document.querySelector("[data-config-dialog]");
    if (!dialog) return;
    var form = dialog.querySelector("[data-config-form]");
    var fieldsRoot = dialog.querySelector("[data-config-fields]");
    var tabsRoot = dialog.querySelector("[data-config-field-tabs]");
    var currentFields = [];
    var editAction = form.getAttribute("action");
    var createAction = dialog.dataset.configCreateUrl || "";
    var createTemplatesNode = document.querySelector("[data-config-create-templates]");
    var createTemplates = createTemplatesNode ? JSON.parse(createTemplatesNode.textContent || "[]") : [];
    var variantInput = form.querySelector('input[name="variant"]');
    if (!variantInput) { variantInput = document.createElement("input"); variantInput.type = "hidden"; variantInput.name = "variant"; form.appendChild(variantInput); }
    if (!form.querySelector('input[name="direct_save"]')) { var directSave = document.createElement("input"); directSave.type = "hidden"; directSave.name = "direct_save"; directSave.value = "yes"; form.appendChild(directSave); }

    // Turn the shared generic dialog markup into the compact PAN-OS editor.
    var brand = dialog.querySelector(":scope > .push-dialog-brand"); if (brand) brand.remove();
    form.classList.remove("bulk-dialog-body"); form.classList.add("config-dialog-layout");
    var header = form.querySelector(".card-header"); if (header) {
      header.classList.remove("card-header"); header.classList.add("config-dialog-header");
      var titleBox = header.querySelector("div");
      if (titleBox) { var eyebrow = document.createElement("p"); eyebrow.className = "eyebrow"; eyebrow.textContent = "OCD · PAN-OS configuratie"; titleBox.insertBefore(eyebrow, titleBox.firstChild); }
      var close = document.createElement("button"); close.type = "button"; close.className = "config-dialog-close"; close.dataset.configCancel = ""; close.setAttribute("aria-label", "Sluiten"); close.textContent = "×"; header.appendChild(close);
    }
    fieldsRoot.classList.add("config-dialog-scroll");
    var actions = form.querySelector(".bulk-dialog-actions"); if (actions) actions.classList.add("config-dialog-footer");

    function setupFamilyTabs() {
      var rows = all("[data-config-record-row]");
      if (!rows.length) return;
      rows.forEach(function (row) { try { var record = JSON.parse(row.getAttribute("data-config-record")); row.dataset.configFamily = record.ui_family || "Other"; row.dataset.configCreatable = record.is_entry ? "true" : "false"; } catch (error) { row.dataset.configFamily = "Other"; row.dataset.configCreatable = "false"; } });
      var families = [];
      rows.filter(function (row) { return row.dataset.configCreatable === "true"; }).forEach(function (row) { var family = row.dataset.configFamily || "Other"; if (!families.includes(family)) families.push(family); });
      rows.filter(function (row) { return row.dataset.configCreatable !== "true"; }).forEach(function (row) { var family = row.dataset.configFamily || "Other"; if (!families.includes(family)) families.push(family); });
      if (families.length < 2) return;
      var table = rows[0].closest(".config-record-list"); var filter = table && table.querySelector(".policy-filterbar"); if (!filter) return;
      var root = document.createElement("div"); root.className = "config-family-tabs"; root.setAttribute("aria-label", "Configuratietypes"); filter.parentNode.insertBefore(root, filter);
      ["All"].concat(families).forEach(function (family) {
        var initiallyActive = family === families[0];
        var button = document.createElement("button"); button.type = "button"; button.className = "btn btn-small" + (initiallyActive ? " is-active" : ""); button.textContent = family;
        button.addEventListener("click", function () {
          all("button", root).forEach(function (item) { item.classList.toggle("is-active", item === button); });
          rows.forEach(function (row) { row.dataset.tableFamilyMatch = String(family === "All" || row.dataset.configFamily === family); updateTableRowVisibility(row); });
        });
        root.appendChild(button);
      });
      rows.forEach(function (row) { row.dataset.tableFamilyMatch = String(row.dataset.configFamily === families[0]); updateTableRowVisibility(row); });
    }

    function tokenEditor(field, wrapper) {
      var values = (field.values || []).slice();
      var box = document.createElement("div"); box.className = "token-input config-token-input";
      var chips = document.createElement("div"); chips.className = "token-chip-list";
      var input = document.createElement("input"); input.placeholder = "Waarde zoeken of freeform toevoegen";
      var add = document.createElement("button"); add.type = "button"; add.className = "btn"; add.textContent = "+";
      function render() {
        chips.innerHTML = "";
        values.forEach(function (value) {
          var chip = document.createElement("span"); chip.className = "policy-value-chip";
          var text = document.createElement("span"); text.textContent = value;
          var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.setAttribute("aria-label", value + " verwijderen");
          remove.addEventListener("click", function () { values = values.filter(function (item) { return item !== value; }); field._values = values; render(); });
          chip.appendChild(text); chip.appendChild(remove); chips.appendChild(chip);
        });
      }
      function append() { parseTagTokens(input.value).forEach(function (value) { if (!values.includes(value)) values.push(value); }); input.value = ""; field._values = values; render(); }
      add.addEventListener("click", append);
      input.addEventListener("keydown", function (event) { if (event.key === "Enter" && !tagQuoteOpen(input.value)) { event.preventDefault(); append(); } });
      field._commit = append; field._values = values;
      box.appendChild(chips); box.appendChild(input); box.appendChild(add); wrapper.appendChild(box); render();
    }

    function activateGroup(group) {
      all("button", tabsRoot).forEach(function (button) { button.classList.toggle("is-active", button.dataset.configGroup === group); });
      all("[data-config-group-panel]", fieldsRoot).forEach(function (panel) { panel.classList.toggle("is-active", panel.dataset.configGroupPanel === group); });
    }

    function renderRecord(item, createMode) {
      form.setAttribute("action", createMode && item.create_variant && createAction ? createAction : editAction);
      variantInput.value = createMode ? item.create_variant || "" : "";
      currentFields = item.edit_fields || [];
      form.querySelector("[data-config-locator]").value = item.locator || "";
      dialog.querySelector("[data-config-dialog-title]").textContent = (createMode ? "Add " + item.kind : "Edit " + item.name);
      dialog.querySelector("[data-config-dialog-kind]").textContent = item.kind;
      dialog.querySelector("[data-config-dialog-owner]").textContent = item.owner;
      var primary = form.querySelector('button.btn-primary[name="operation"]');
      if (primary) { primary.value = createMode ? "create" : "update"; primary.textContent = "Save"; }
      tabsRoot.innerHTML = ""; fieldsRoot.innerHTML = "";
      var groups = (item.ui_tabs || []).slice();
      currentFields.forEach(function (field) { var group = field.group || "General"; if (!groups.includes(group)) groups.push(group); });
      if (!groups.length) groups.push("General");
      groups.forEach(function (group, index) {
        var tab = document.createElement("button"); tab.type = "button"; tab.dataset.configGroup = group; tab.textContent = group; if (!index) tab.classList.add("is-active");
        tab.addEventListener("click", function () { activateGroup(group); }); tabsRoot.appendChild(tab);
        var panel = document.createElement("div"); panel.className = "policy-tab-panel config-field-panel" + (!index ? " is-active" : ""); panel.dataset.configGroupPanel = group;
        var grid = document.createElement("div"); grid.className = "form-grid";
        currentFields.filter(function (field) { return (field.group || "General") === group; }).forEach(function (field) {
          var wrapper = document.createElement("div"); wrapper.className = "field full config-generic-field";
          var label = document.createElement("label"); label.textContent = field.label; wrapper.appendChild(label);
          if (field.kind === "protected") {
            var protectedText = document.createElement("div"); protectedText.className = "callout"; protectedText.textContent = "Beschermde waarde · blijft ongewijzigd"; wrapper.appendChild(protectedText);
          } else if (field.kind === "members") tokenEditor(field, wrapper);
          else if (field.kind === "boolean" || field.kind === "bool") {
            var booleanValues = field.kind === "bool" ? ["true", "false"] : ["yes", "no"];
            if (field.optional) booleanValues.unshift("");
            var select = document.createElement("select"); booleanValues.forEach(function (value) { var option = document.createElement("option"); option.value = value; option.textContent = value === "" ? "Niet ingesteld" : value; option.selected = String(field.value == null ? "" : field.value).trim().toLowerCase() === value; select.appendChild(option); }); field._input = select; wrapper.appendChild(select);
          } else {
            var input;
            if (field.options && field.options.length) {
              input = document.createElement("select");
              var current = String(field.value == null ? "" : field.value);
              var options = field.options.slice(); if (current && !options.includes(current)) options.unshift(current);
              options.forEach(function (value) { var option = document.createElement("option"); option.value = value; option.textContent = value === "" && field.optional ? "Niet ingesteld" : value; option.selected = value === current; input.appendChild(option); });
            } else {
              input = field.kind === "json" || String(field.value || "").length > 180 ? document.createElement("textarea") : document.createElement("input"); input.value = field.value == null ? "" : field.value; if (input.tagName === "TEXTAREA") input.rows = field.kind === "json" ? 8 : 4;
              input.maxLength = Number.isInteger(field.max_length) && field.max_length > 0 ? Math.min(field.max_length, 65535) : 65535;
            }
            input.required = Boolean(field.required);
            field._input = input; wrapper.appendChild(input);
          }
          if (field.technical_label && field.technical_label !== field.label) { var path = document.createElement("small"); path.className = "config-field-path"; path.textContent = field.technical_label; wrapper.appendChild(path); }
          grid.appendChild(wrapper);
        });
        if (item.is_entry && index === 0) {
          var nameField = document.createElement("div"); nameField.className = "field full config-generic-field config-name-field";
          var nameLabel = document.createElement("label"); nameLabel.textContent = "Name";
          var nameInput = document.createElement("input"); nameInput.name = "name"; nameInput.required = true; nameInput.maxLength = Number.isInteger(item.name_max_length) && item.name_max_length > 0 ? Math.min(item.name_max_length, 127) : 127; nameInput.value = createMode ? "" : item.name; nameInput.placeholder = createMode ? "Nieuwe unieke naam" : "";
          nameField.appendChild(nameLabel); nameField.appendChild(nameInput); grid.insertBefore(nameField, grid.firstChild);
        } else if (!item.is_entry && index === 0) {
          var hiddenName = document.createElement("input"); hiddenName.type = "hidden"; hiddenName.name = "name"; hiddenName.value = item.name; grid.appendChild(hiddenName);
        }
        panel.appendChild(grid); fieldsRoot.appendChild(panel);
      });
      activateGroup(groups[0]); dialog.showModal();
      var first = dialog.querySelector("input:not([type=hidden]), select, textarea"); if (first) first.focus({preventScroll:true});
    }

    all("[data-config-record-edit]").forEach(function (button) { button.addEventListener("click", function () { renderRecord(JSON.parse(button.closest("[data-config-record-row]").getAttribute("data-config-record")), false); }); });
    all("[data-config-cancel]", dialog).forEach(function (button) { button.addEventListener("click", function () { dialog.close(); }); });
    dialog.addEventListener("click", function (event) { if (event.target === dialog) dialog.close(); });
    form.addEventListener("submit", function () {
      currentFields.forEach(function (field) { if (field._commit) field._commit(); });
      var updates = currentFields.filter(function (field) {
        if (field.kind === "protected") return false;
        if (field.kind === "members") return JSON.stringify(field._values || []) !== JSON.stringify(field.values || []);
        return String(field._input ? field._input.value : field.value || "") !== String(field.value == null ? "" : field.value);
      }).map(function (field) {
        return field.kind === "members" ? {path:field.path,kind:field.kind,values:field._values || []} : {path:field.path,kind:field.kind,value:field._input ? field._input.value : field.value || ""};
      });
      form.querySelector("[data-config-updates]").value = JSON.stringify(updates);
    });

    var checks = all("[data-config-record-select]");
    var count = document.querySelector("[data-config-selected-count]");
    var remove = document.querySelector("[data-config-delete]");
    var deleteForm = remove && remove.closest("form");
    if (deleteForm && !deleteForm.querySelector('input[name="direct_save"]')) { var directDelete = document.createElement("input"); directDelete.type = "hidden"; directDelete.name = "direct_save"; directDelete.value = "yes"; deleteForm.appendChild(directDelete); }
    function updateSelection() { var selected = checks.filter(function (check) { return check.checked; }).length; if (count) count.textContent = selected; if (remove) remove.disabled = selected === 0; }
    checks.forEach(function (check) { check.addEventListener("change", updateSelection); }); updateSelection();
    setupFamilyTabs();
    var actionbar = remove && remove.closest(".object-actionbar");
    var creatableRows = all("[data-config-record-row]").filter(function (row) { return row.dataset.configCreatable === "true"; });
    if (actionbar && !creatableRows.length && !createTemplates.length) actionbar.hidden = true;
    if (actionbar && (creatableRows.length || createTemplates.length)) {
      var createType = null;
      if (createTemplates.length > 1) {
        createType = document.createElement("select"); createType.className = "config-create-type"; createType.dataset.configCreateVariant = ""; createType.setAttribute("aria-label", "Nieuw configuratietype");
        createTemplates.forEach(function (item, index) { var option = document.createElement("option"); option.value = String(index); option.textContent = item.label || item.kind || item.ui_family; createType.appendChild(option); });
        actionbar.insertBefore(createType, remove);
      }
      var add = document.createElement("button"); add.type = "button"; add.className = "btn btn-primary"; add.textContent = "+ Add"; add.dataset.configAdd = "";
      add.addEventListener("click", function () {
        if (createTemplates.length) {
          var template = createTemplates[createType ? Number(createType.value) : 0];
          renderRecord(JSON.parse(JSON.stringify(template)), true);
          return;
        }
        var rows = all("[data-config-record-row]");
        var checked = rows.find(function (row) { var check = row.querySelector("[data-config-record-select]"); return row.dataset.configCreatable === "true" && check && check.checked; });
        var base = checked || rows.find(function (row) { return row.dataset.configCreatable === "true" && !row.hidden && row.style.display !== "none"; }) || rows.find(function (row) { return row.dataset.configCreatable === "true"; });
        if (!base) return;
        renderRecord(JSON.parse(base.getAttribute("data-config-record")), true);
      });
      actionbar.insertBefore(add, remove);
    }
  }

  function setupWorkspaceObjects() {
    var dialog = document.querySelector("[data-workspace-object-dialog]");
    if (!dialog) return;
    all("[data-workspace-object]").forEach(function (button) {
      button.addEventListener("click", function () {
        var item = JSON.parse(button.getAttribute("data-workspace-object"));
        dialog.querySelector("[data-workspace-object-title]").textContent = item.name;
        dialog.querySelector("[data-workspace-object-owner]").textContent = item.owner + (item.editable ? " · lokale scope" : " · inherited · aanpassen in de owning scope");
        var fields = dialog.querySelector("[data-workspace-object-fields]");
        fields.innerHTML = "";
        (item.fields || []).forEach(function (field) {
          var wrapper = document.createElement("div"); wrapper.className = "field";
          var label = document.createElement("label"); label.textContent = field.name.replace(/-/g, " ");
          var values = document.createElement("div"); values.className = "policy-value-editor";
          (field.values || []).forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var text = document.createElement("span"); text.textContent = value; chip.appendChild(text); values.appendChild(chip); });
          wrapper.appendChild(label); wrapper.appendChild(values); fields.appendChild(wrapper);
        });
        if (!fields.children.length) fields.textContent = "Geen configureerbare velden gevonden.";
        dialog.showModal();
      });
    });
    dialog.querySelector("[data-workspace-object-close]").addEventListener("click", function () { dialog.close(); });
  }

  function setupWorkspaceContextLoading() {
    var form = document.querySelector(".workspace-scope-bar");
    if (!form) return;
    all("select", form).forEach(function (select) {
      select.removeAttribute("onchange");
      select.addEventListener("change", function () {
        document.body.classList.add("workspace-context-loading");
        var status = document.createElement("div");
        status.className = "workspace-loading-status";
        status.setAttribute("role", "status");
        status.innerHTML = '<div class="progress"><div class="progress-bar progress-indeterminate"></div></div><strong>Configuratie laden…</strong><span>De gekozen context wordt behouden.</span>';
        document.body.appendChild(status);
        var query = new URLSearchParams(new FormData(form)).toString();
        var target = form.getAttribute("action") || window.location.pathname;
        window.requestAnimationFrame(function () { window.location.assign(target + "?" + query); });
      });
    });
  }

  function setupMigrationTargetDialog() {
    var dialog = document.querySelector("[data-migration-target-dialog]");
    var open = document.querySelector("[data-migration-target-open]");
    if (!dialog || !open) return;
    var projectName = document.querySelector("[data-migration-project-name]");
    var draft = dialog.querySelector("[data-migration-target-draft]");
    open.addEventListener("click", function () {
      if (draft) draft.value = projectName ? projectName.value : "";
      dialog.showModal();
    });
    var close = dialog.querySelector("[data-migration-target-close]");
    if (close) close.addEventListener("click", function () { dialog.close(); });
    dialog.addEventListener("click", function (event) {
      if (event.target === dialog) dialog.close();
    });
  }

  function setupPolicyMemberDialogs() {
    var dialog = document.createElement("dialog");
    dialog.className = "policy-members-dialog push-dialog";
    dialog.innerHTML = '<div class="push-dialog-brand">POLICYWAARDEN</div>' +
      '<div class="push-dialog-body"><div class="card-header"><h2>Alle waarden</h2>' +
      '<button class="config-dialog-close" type="button" aria-label="Sluiten">×</button></div>' +
      '<input class="search" type="search" placeholder="Zoek in deze waarden" data-policy-members-search>' +
      '<div class="policy-members-dialog-list" data-policy-members-list></div></div>';
    document.body.appendChild(dialog);
    var values = [];
    var list = dialog.querySelector("[data-policy-members-list]");
    var search = dialog.querySelector("[data-policy-members-search]");
    function render() {
      var query = search.value.toLocaleLowerCase().trim();
      list.innerHTML = "";
      values.filter(function (value) { return !query || value.toLocaleLowerCase().includes(query); }).forEach(function (value) {
        var row = document.createElement("span"); row.textContent = value; list.appendChild(row);
      });
    }
    document.addEventListener("click", function (event) {
      var button = event.target.closest("[data-policy-members]");
      if (!button) return;
      try { values = JSON.parse(button.dataset.policyMembers || "[]").map(String); }
      catch (_error) { values = []; }
      search.value = ""; render(); dialog.showModal(); search.focus();
    });
    search.addEventListener("input", render);
    dialog.querySelector(".config-dialog-close").addEventListener("click", function () { dialog.close(); });
    dialog.addEventListener("click", function (event) { if (event.target === dialog) dialog.close(); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    restorePolicyBulkState();
    setupPolicyBulkStatePersistence();
    function runSetup(name, callback) {
      try { callback(); }
      catch (error) { console.error("PA Policy Forge UI setup failed: " + name, error); }
    }
    runSetup("navigation", setupNavigation);
    runSetup("sidebar", setupSidebarCollapse);
    runSetup("config-tree", setupConfigTree);
    runSetup("passwords", setupPasswords);
    runSetup("confirmations", setupConfirmations);
    runSetup("flashes", setupFlashes);
    runSetup("bulk-selection", setupBulkSelection);
    runSetup("filters", setupFilters);
    runSetup("migration-review-search", setupMigrationReviewSearch);
    runSetup("object-search", setupObjectSearchSubmit);
    runSetup("migration-filter-types", setupMigrationFilterTypes);
    runSetup("migration-zone-mapping", setupMigrationZoneMapping);
    runSetup("targets", setupConditionalTargets);
    runSetup("vsys-mode", setupVsysMode);
    runSetup("migration-target-dialog", setupMigrationTargetDialog);
    runSetup("policy-member-dialogs", setupPolicyMemberDialogs);
    runSetup("push-options", setupPushOptions);
    runSetup("policy-management", setupPolicyManagement);
    runSetup("object-management", setupObjectManagement);
    runSetup("offline-policy", setupOfflinePolicyTabs);
    runSetup("configuration-editor", setupWorkspaceConfigurationEditor);
    runSetup("pull-progress", setupConfigPullProgress);
    runSetup("incremental-push-controls", setupIncrementalPushControls);
    runSetup("workspace-commit-status", setupCommitStatusPolling);
    runSetup("workspace-objects", setupWorkspaceObjects);
    runSetup("workspace-context", setupWorkspaceContextLoading);
  });
})();
