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
    }
    rows.forEach(function (row, rowIndex) {
      var checkbox = row.querySelector("[data-policy-select]");
      if (!checkbox) return;
      checkbox.addEventListener("click", function (event) {
        if ((event.ctrlKey || event.shiftKey) && lastSelectedIndex !== null) {
          var start = Math.min(lastSelectedIndex, rowIndex); var end = Math.max(lastSelectedIndex, rowIndex);
          for (var i = start; i <= end; i += 1) { var rangeCheckbox = rows[i].querySelector("[data-policy-select]"); if (rangeCheckbox) rangeCheckbox.checked = true; }
          checkbox.checked = true;
        }
      });
      checkbox.addEventListener("change", function () { lastSelectedIndex = rowIndex; updateActionCount(); });
      row.addEventListener("click", function (event) {
        if (event.target.closest("input,button,a,select")) return;
        if ((event.ctrlKey || event.shiftKey) && lastSelectedIndex !== null) {
          var start = Math.min(lastSelectedIndex, rowIndex); var end = Math.max(lastSelectedIndex, rowIndex);
          for (var i = start; i <= end; i += 1) { var rangeCheckbox = rows[i].querySelector("[data-policy-select]"); if (rangeCheckbox) rangeCheckbox.checked = true; }
        } else checkbox.checked = !checkbox.checked;
        lastSelectedIndex = rowIndex; updateActionCount();
      });
    });

    var singleDialog = document.querySelector("[data-policy-single-dialog]");
    if (singleDialog) {
      var singleTagInput = singleDialog.querySelector("[data-single-tag-input]"); var singleTagEntry = singleDialog.querySelector("[data-single-tag-entry]"); var singleTagSet = new Set();
      function renderSingleTags() { var container = singleDialog.querySelector("[data-single-tag-values]"); if (!container) return; container.innerHTML = ""; singleTagSet.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { singleTagSet.delete(value); singleTagInput.value = Array.from(singleTagSet).join(","); renderSingleTags(); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); }); if (!singleTagSet.size) { var empty = document.createElement("span"); empty.className = "muted small"; empty.textContent = "Geen tags"; container.appendChild(empty); } }
      function addSingleTags(value) { parseTagTokens(value).forEach(function (tag) { singleTagSet.add(tag); }); if (singleTagInput) singleTagInput.value = Array.from(singleTagSet).join(","); if (singleTagEntry) singleTagEntry.value = ""; renderSingleTags(); }
      if (singleTagEntry) { singleTagEntry._addTagValue = function (value) { addSingleTags(value); }; singleTagEntry.addEventListener("keydown", function (event) { if (event.key === "Enter" || event.key === "," || (event.key === " " && !tagQuoteOpen(singleTagEntry.value))) { event.preventDefault(); addSingleTags(singleTagEntry.value); } }); }
      var singleTagAdd = singleDialog.querySelector("[data-single-tag-add]"); if (singleTagAdd) singleTagAdd.addEventListener("click", function () { addSingleTags(singleTagEntry.value); });
      var singleTokenFields = all("[data-single-token-field]", singleDialog);
      singleTokenFields.forEach(function (fieldNode) {
        var hidden = fieldNode.querySelector("[data-single-token-input]"); var entry = fieldNode.querySelector("[data-single-token-entry]"); var valuesNode = fieldNode.querySelector("[data-single-token-values]"); var valueSet = new Set();
        function syncSingleTokens() { hidden.value = Array.from(valueSet).join(","); valuesNode.innerHTML = ""; valueSet.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { valueSet.delete(value); syncSingleTokens(); }); chip.appendChild(label); chip.appendChild(remove); valuesNode.appendChild(chip); }); if (!valueSet.size) { var empty = document.createElement("span"); empty.className = "muted small"; empty.textContent = "Geen waarden"; valuesNode.appendChild(empty); } }
        function addSingleToken(value) { value.split(",").map(function (item) { return item.trim(); }).filter(Boolean).forEach(function (item) { valueSet.add(item); }); entry.value = ""; syncSingleTokens(); }
        fieldNode._setTokenValues = function (values) { valueSet = new Set(Array.isArray(values) ? values : values ? [values] : []); syncSingleTokens(); };
        entry._addTokenValue = addSingleToken; entry.addEventListener("keydown", function (event) { if (event.key === "Enter" || event.key === ",") { event.preventDefault(); addSingleToken(entry.value); } });
        fieldNode.querySelector("[data-single-token-add]").addEventListener("click", function () { addSingleToken(entry.value); }); syncSingleTokens();
      });
      var singleForm = singleDialog.querySelector("[data-policy-single-form]"); if (singleForm) singleForm.addEventListener("submit", function () { if (singleTagEntry && singleTagEntry.value.trim()) addSingleTags(singleTagEntry.value); singleTokenFields.forEach(function (fieldNode) { var entry = fieldNode.querySelector("[data-single-token-entry]"); if (entry.value.trim()) entry._addTokenValue(entry.value); }); });
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

    var valuePicker = document.querySelector("[data-policy-value-picker]"); var policyCatalogNode = document.querySelector("[data-policy-catalog]");
    if (valuePicker && policyCatalogNode) {
      var policyCatalog = JSON.parse(policyCatalogNode.textContent || "[]"); var pickerTarget = null; var pickerSelections = new Set();
      var bulkFormForCatalog = document.querySelector("[data-policy-bulk-form]"); var catalogProfileMatch = bulkFormForCatalog ? bulkFormForCatalog.action.match(/\/policies\/(\d+)\/preview/) : null; var workspaceApplicationState = document.querySelector("[data-workspace-application-catalog]"); var applicationPolls = 0;
      var pickerKinds = {from:["zones"],to:["zones"],source:["addresses","address-groups"],destination:["addresses","address-groups"],application:["applications","application-groups","application-filters"],service:["services","service-groups"],tag:["tags"],source_user:["$current"],destination_user:["$current"],source_hip:["$current"],destination_hip:["$current"],category:["$current"],schedule:["$current"],log_setting:["$current"],profile_group:["$current"]};
      function addPickedValue(name) { if (!pickerTarget) return; if (typeof pickerTarget._addTagValue === "function") { pickerTarget._addTagValue(name); } else if (typeof pickerTarget._addTokenValue === "function") { pickerTarget._addTokenValue(name); } else if (pickerTarget.hasAttribute("data-bulk-entry")) { pickerTarget.value = name; pickerTarget.closest("[data-bulk-field]").querySelector("[data-bulk-add-button]").click(); } else { var values = pickerTarget.value.split(",").map(function (value) { return value.trim(); }).filter(Boolean); if (!values.includes(name)) values.push(name); pickerTarget.value = values.join(", "); } }
      function updatePickerCount() { var count = valuePicker.querySelector("[data-policy-picker-selected-count]"); if (count) count.textContent = pickerSelections.size; }
      function renderPolicyPicker(query) { var field = pickerTarget ? pickerTarget.dataset.pickerField : ""; var kinds = pickerKinds[field] || []; var candidates = policyCatalog.filter(function (item) { return kinds.includes(item.kind); }); if (kinds.includes("$current")) { var datasetKeys = {source_user:"sourceUser",destination_user:"destinationUser",source_hip:"sourceHip",destination_hip:"destinationHip",profile_group:"profileGroup",log_setting:"logSetting"}; var key = datasetKeys[field] || field; var seen = new Set(); rows.forEach(function (policyRow) { (policyRow.dataset[key] || "").split("|||").filter(Boolean).forEach(function (name) { if (!seen.has(name)) { seen.add(name); candidates.push({name:name,kind:"huidige rulebase"}); } }); }); } var results = valuePicker.querySelector("[data-policy-picker-results]"); results.innerHTML = ""; candidates.filter(function (item) { return !query || item.name.toLocaleLowerCase().includes(query); }).forEach(function (item) { var row = document.createElement("div"); row.className = "member-result" + (pickerSelections.has(item.name) ? " is-selected" : ""); var copy = document.createElement("div"); var strong = document.createElement("strong"); strong.textContent = item.name; var small = document.createElement("small"); small.textContent = item.kind; copy.appendChild(strong); copy.appendChild(small); var button = document.createElement("button"); button.className = "btn btn-small"; button.type = "button"; button.textContent = pickerSelections.has(item.name) ? "Geselecteerd" : "Selecteer"; button.addEventListener("click", function () { if (pickerSelections.has(item.name)) pickerSelections.delete(item.name); else pickerSelections.add(item.name); updatePickerCount(); renderPolicyPicker(query); }); row.appendChild(copy); row.appendChild(button); results.appendChild(row); }); if (!results.children.length) { var empty = document.createElement("div"); empty.className = "muted member-result"; empty.textContent = "Geen bestaande waarden gevonden; freeform blijft mogelijk"; results.appendChild(empty); } updatePickerCount(); }
      function showApplicationError(message) { if (!message || !pickerTarget || pickerTarget.dataset.pickerField !== "application") return; var results = valuePicker.querySelector("[data-policy-picker-results]"); var warning = document.createElement("div"); warning.className = "callout member-result"; warning.textContent = "Applicatiecatalogus niet bijgewerkt: " + message; results.prepend(warning); }
      function showApplicationStatus(data) { var status = valuePicker.querySelector("[data-policy-picker-status]"); if (!status) return; status.textContent = data.error ? "Applicatiecatalogus kon niet worden bijgewerkt." : data.ready ? data.items.length + " applicaties beschikbaar." : data.refreshing ? "Application database wordt geladen…" : "Geen application database beschikbaar."; }
      function loadApplications() { var catalogUrl = catalogProfileMatch ? "/profiles/" + catalogProfileMatch[1] + "/catalog/applications" : workspaceApplicationState ? workspaceApplicationState.dataset.workspaceApplicationCatalog : ""; if (!catalogUrl) return; var initialStatus = valuePicker.querySelector("[data-policy-picker-status]"); if (initialStatus) initialStatus.textContent = "Application database wordt geladen…"; fetch(catalogUrl, {headers:{"Accept":"application/json"}}).then(function (response) { if (!response.ok) throw new Error("HTTP " + response.status); return response.json(); }).then(function (data) { var existing = new Set(policyCatalog.filter(function (item) { return item.kind === "applications"; }).map(function (item) { return item.name; })); (data.items || []).forEach(function (item) { if (!existing.has(item.name)) policyCatalog.push(item); }); showApplicationStatus(data); if (pickerTarget && pickerTarget.dataset.pickerField === "application") { renderPolicyPicker((valuePicker.querySelector("[data-policy-picker-filter]").value || "").toLocaleLowerCase()); showApplicationError(data.error); } if (!data.ready && data.refreshing && applicationPolls < 40) { applicationPolls += 1; setTimeout(loadApplications, 3000); } }).catch(function (error) { showApplicationError(error.message); }); }
      function openPolicyValuePicker(input, fieldName) { pickerTarget = input; pickerTarget.dataset.pickerField = fieldName || input.dataset.pickerField; pickerSelections.clear(); var pickerStatus = valuePicker.querySelector("[data-policy-picker-status]"); if (pickerStatus) pickerStatus.textContent = ""; var activeDialog = input.closest("dialog"); if (activeDialog && valuePicker.parentElement !== activeDialog) activeDialog.appendChild(valuePicker); valuePicker.hidden = false; valuePicker.querySelector("[data-policy-picker-title]").textContent = "Bestaande waarden voor " + pickerTarget.dataset.pickerField; var filter = valuePicker.querySelector("[data-policy-picker-filter]"); filter.value = ""; renderPolicyPicker(""); if (pickerTarget.dataset.pickerField === "application") { applicationPolls = 0; loadApplications(); } }
      all("[data-picker-field]").forEach(function (input) { if (!pickerKinds[input.dataset.pickerField]) return; input.addEventListener("focus", function () { openPolicyValuePicker(input); }); });
      var singleTagPicker = document.querySelector("[data-single-tag-picker]"); if (singleTagPicker && singleTagEntry) singleTagPicker.addEventListener("click", function () { openPolicyValuePicker(singleTagEntry, "tag"); });
      valuePicker.querySelector("[data-policy-picker-filter]").addEventListener("input", function (event) { renderPolicyPicker(event.target.value.toLocaleLowerCase().trim()); });
      valuePicker.querySelector("[data-policy-picker-close]").addEventListener("click", function () { valuePicker.hidden = true; });
      var addSelected = valuePicker.querySelector("[data-policy-picker-add-selected]"); if (addSelected) addSelected.addEventListener("click", function () { pickerSelections.forEach(addPickedValue); pickerSelections.clear(); updatePickerCount(); valuePicker.hidden = true; });
    }

    var dialog = document.querySelector("[data-policy-bulk-dialog]");
    var opener = document.querySelector("[data-open-policy-bulk]");
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
      if (!count) { window.alert("Selecteer minstens één policy."); return; }
      dialog.querySelector("[data-policy-selected-count]").textContent = count;
      prepareBulkFields();
      dialog.showModal();
    });
    all("[data-bulk-field]", dialog).forEach(function (fieldNode) {
      var input = fieldNode.querySelector("[data-bulk-entry]"); var hidden = fieldNode.querySelector("[data-bulk-add]"); var button = fieldNode.querySelector("[data-bulk-add-button]");
      function addValue() {
        var additions = splitEntry(input.value, fieldNode.dataset.bulkField); if (!additions.length) return;
        additions.forEach(function (value) { fieldNode._addedValues.add(value); });
        hidden.value = Array.from(fieldNode._addedValues).join(","); input.value = "";
        renderBulkField(fieldNode, fieldNode._currentValues, fieldNode._removedValues, fieldNode._addedValues);
      }
      fieldNode._addBulkValue = addValue;
      button.addEventListener("click", addValue);
      input.addEventListener("keydown", function (event) { var tagDelimiter = fieldNode.dataset.bulkField === "tag" && (event.key === "," || (event.key === " " && !tagQuoteOpen(input.value))); if (event.key === "Enter" || tagDelimiter) { event.preventDefault(); addValue(); } });
    });
    var policyBulkForm = document.querySelector("[data-policy-bulk-form]"); if (policyBulkForm) policyBulkForm.addEventListener("submit", function () { all("[data-bulk-field]", dialog).forEach(function (fieldNode) { var entry = fieldNode.querySelector("[data-bulk-entry]"); if (entry && entry.value.trim()) fieldNode._addBulkValue(); }); });
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

  function setupObjectManagement() {
    var dialog = document.querySelector("[data-object-dialog]");
    var form = document.querySelector("[data-object-form]");
    if (dialog) { var objectTabs = dialog.querySelector(".policy-tabs"); if (objectTabs && objectTabs.querySelectorAll("button:not([disabled])").length <= 1) objectTabs.remove(); }
    var rows = all("[data-object-row]");
    var checkboxes = all("[data-object-select]");
    var countNode = document.querySelector("[data-object-selected-count]");
    var deleteButton = document.querySelector("[data-object-delete]");
    function updateCount() { var count = checkboxes.filter(function (item) { return item.checked; }).length; if (countNode) countNode.textContent = count; if (deleteButton) deleteButton.disabled = !count; }
    checkboxes.forEach(function (checkbox) { checkbox.addEventListener("change", updateCount); });
    var master = document.querySelector("[data-object-select-visible]");
    if (master) master.addEventListener("change", function () { rows.forEach(function (row) { var checkbox = row.querySelector("[data-object-select]"); if (checkbox && !row.hidden) checkbox.checked = master.checked; }); updateCount(); });
    var detailDialog = document.querySelector("[data-object-detail-dialog]");
    if (detailDialog) {
      rows.forEach(function (row) { var button = row.querySelector("[data-object-detail]"); if (!button) return; var item = JSON.parse(row.dataset.object); button.addEventListener("click", function () { detailDialog.querySelector("[data-object-detail-title]").textContent = item.name; var body = detailDialog.querySelector("[data-object-detail-body]"); body.innerHTML = ""; Object.keys(item).filter(function (key) { return key.charAt(0) !== "_"; }).sort().forEach(function (key) { var tr = document.createElement("tr"); var name = document.createElement("td"); name.textContent = key; var value = document.createElement("td"); value.className = "mono"; value.textContent = typeof item[key] === "object" ? JSON.stringify(item[key]) : item[key]; tr.appendChild(name); tr.appendChild(value); body.appendChild(tr); }); detailDialog.showModal(); }); });
      detailDialog.querySelector("[data-object-detail-close]").addEventListener("click", function () { detailDialog.close(); });
    }
    if (!dialog || !form) { updateCount(); return; }
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
    var dynamicInput = form.querySelector("[data-dynamic-input]"); var dynamicEntry = form.querySelector("[data-dynamic-entry]"); var dynamicTokens = [];
    function dynamicExpressionTokens(value) { return String(value || "").match(/'[^']*'|"[^"]*"|\(|\)|[^\s()]+/g) || []; }
    function renderDynamicTokens() { var container = form.querySelector("[data-dynamic-values]"); if (!container) return; container.innerHTML = ""; dynamicTokens.forEach(function (value, index) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.title = "Expressiedeel verwijderen"; remove.addEventListener("click", function () { dynamicTokens.splice(index, 1); syncDynamicFilter(); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); }); }
    function syncDynamicFilter() { if (dynamicInput) dynamicInput.value = dynamicTokens.join(" "); renderDynamicTokens(); }
    function setDynamicFilter(value) { dynamicTokens = dynamicExpressionTokens(value); if (dynamicEntry) dynamicEntry.value = ""; syncDynamicFilter(); }
    function dynamicQuoteOpen(value) { var single = (value.match(/'/g) || []).length; var double = (value.match(/"/g) || []).length; return single % 2 === 1 || double % 2 === 1; }
    function commitDynamicEntry() { if (!dynamicEntry) return; var value = dynamicEntry.value.trim(); if (!value) return; dynamicTokens = dynamicTokens.concat(dynamicExpressionTokens(value)); dynamicEntry.value = ""; syncDynamicFilter(); }
    if (dynamicEntry) dynamicEntry.addEventListener("keydown", function (event) { if ((event.key === " " && !dynamicQuoteOpen(dynamicEntry.value)) || event.key === "Enter") { event.preventDefault(); commitDynamicEntry(); } });
    function setField(name, value) { var field = form.querySelector('[data-object-field="' + name + '"]'); if (!field) return; field.value = Array.isArray(value) ? value.join(", ") : (value == null ? "" : value); }
    var genericEditor = dialog.dataset.genericObjectEditor === "true";
    var genericUpdates = [];
    function syncGenericUpdates() { var target = form.querySelector("[data-generic-object-updates]"); if (target) target.value = JSON.stringify(genericUpdates); }
    function renderGenericFields(item) {
      var container = form.querySelector("[data-generic-object-fields]"); if (!container) return;
      container.innerHTML = ""; genericUpdates = (item.edit_fields || []).map(function (field) { return {path:field.path, label:field.label, kind:field.kind, value:field.value || "", values:(field.values || []).slice()}; });
      genericUpdates.forEach(function (field) {
        var wrapper = document.createElement("div"); wrapper.className = "field full generic-object-field";
        var label = document.createElement("label"); label.textContent = field.label; wrapper.appendChild(label);
        if (field.kind === "boolean") {
          var select = document.createElement("select"); ["yes", "no"].forEach(function (value) { var option = document.createElement("option"); option.value = value; option.textContent = value === "yes" ? "Yes" : "No"; select.appendChild(option); }); select.value = field.value; select.addEventListener("change", function () { field.value = select.value; syncGenericUpdates(); }); wrapper.appendChild(select);
        } else if (field.kind === "members") {
          var tokenInput = document.createElement("div"); tokenInput.className = "token-input"; var chips = document.createElement("div"); chips.className = "token-chip-list";
          var input = document.createElement("input"); input.placeholder = "Waarde toevoegen"; var addButton = document.createElement("button"); addButton.type = "button"; addButton.className = "btn"; addButton.textContent = "+"; tokenInput.appendChild(chips); tokenInput.appendChild(input); tokenInput.appendChild(addButton);
          function renderValues() { chips.innerHTML = ""; field.values.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var text = document.createElement("span"); text.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { field.values = field.values.filter(function (candidate) { return candidate !== value; }); syncGenericUpdates(); renderValues(); }); chip.appendChild(text); chip.appendChild(remove); chips.appendChild(chip); }); if (!field.values.length) { var empty = document.createElement("span"); empty.className = "muted"; empty.textContent = "Geen waarden"; chips.appendChild(empty); } }
          function addValue() { var value = input.value.trim(); if (value && !field.values.includes(value)) field.values.push(value); input.value = ""; syncGenericUpdates(); renderValues(); }
          addButton.addEventListener("click", addValue); input.addEventListener("keydown", function (event) { if (event.key === "Enter") { event.preventDefault(); addValue(); } }); wrapper.appendChild(tokenInput); renderValues();
        } else {
          var inputField = field.value.length > 160 ? document.createElement("textarea") : document.createElement("input"); inputField.value = field.value; inputField.addEventListener("input", function () { field.value = inputField.value; syncGenericUpdates(); }); wrapper.appendChild(inputField);
        }
        container.appendChild(wrapper);
      });
      if (!genericUpdates.length) { var empty = document.createElement("div"); empty.className = "empty-state"; empty.textContent = "Dit object bevat geen configureerbare waarden."; container.appendChild(empty); }
      syncGenericUpdates();
    }
    function openEditor(item) {
      form.reset(); form.querySelector("[data-object-id]").value = item && item.id ? item.id : "";
      dialog.querySelector("[data-object-dialog-title]").textContent = (item ? "Edit " : "Add ") + document.querySelector(".object-list h2").textContent;
      setMembers([]); setTags([]); setDynamicFilter("");
      var zoneConfig = form.querySelector("[data-zone-current-config]");
      if (!zoneConfig && form.querySelector('[data-object-field="zone_type"]')) { zoneConfig = document.createElement("details"); zoneConfig.className = "zone-current-config field full"; zoneConfig.dataset.zoneCurrentConfig = ""; var summary = document.createElement("summary"); summary.textContent = "Volledige huidige zoneconfig"; var pre = document.createElement("pre"); pre.className = "mono"; zoneConfig.appendChild(summary); zoneConfig.appendChild(pre); form.querySelector(".form-grid").appendChild(zoneConfig); }
      if (zoneConfig) { zoneConfig.hidden = !(item && item.network); if (item && item.network) { var visibleConfig = {}; Object.keys(item).sort().forEach(function (key) { if (!["_xml", "_raw"].includes(key)) visibleConfig[key] = item[key]; }); zoneConfig.querySelector("pre").textContent = JSON.stringify(visibleConfig, null, 2); } }
      if (item) {
        setField("name", item.name); setField("description", item.description); setField("comments", item.comments); setTags(item.tag);
        if (genericEditor) renderGenericFields(item);
        ["ip_netmask", "ip_range", "ip_wildcard", "fqdn"].some(function (kind) { if (item[kind]) { setField("value_type", kind); setField("value", item[kind]); return true; } return false; });
        if (item.dynamic) { if (groupType) groupType.value = "dynamic"; setDynamicFilter(typeof item.dynamic === "object" ? item.dynamic.filter : item.dynamic); } else { if (groupType) groupType.value = "static"; setMembers(item.static); setDynamicFilter(""); }
        if (item.members) setMembers(item.members);
        if (item.protocol) { var protocolName = Object.keys(item.protocol)[0]; var details = item.protocol[protocolName] || {}; setField("protocol_name", protocolName); ["port", "source_port", "timeout", "halfclose_timeout", "timewait_timeout"].forEach(function (key) { setField(key, details[key]); }); if (override) override.checked = Boolean(details.override || details.timeout || details.halfclose_timeout || details.timewait_timeout); }
        if (item.network) { var zoneType = Object.keys(item.network)[0] || "layer3"; var zoneInterfaces = item.network[zoneType] || []; setField("zone_type", zoneType.replace("-", "_")); setField("interfaces", Array.isArray(zoneInterfaces) ? zoneInterfaces : zoneInterfaces.member || []); }
        var userId = form.querySelector('[data-object-field="enable_user_identification"]'); if (userId) userId.checked = item.enable_user_identification === true || item.enable_user_identification === "yes";
        setField("zone_protection_profile", item.zone_protection_profile); setField("log_setting", item.log_setting);
        setField("color", item.color);
      }
      updateGroupType(); updateTimeouts(); dialog.showModal();
    }
    var add = document.querySelector("[data-object-add]"); if (add) add.addEventListener("click", function () { openEditor(null); });
    rows.forEach(function (row) { var button = row.querySelector("[data-object-edit]"); if (!button) return; var item = JSON.parse(row.dataset.object); if (item.network) { var zoneType = Object.keys(item.network)[0] || "onbekend"; var zoneValue = item.network[zoneType] || []; var zoneInterfaces = Array.isArray(zoneValue) ? zoneValue : zoneValue.member || []; var valueCell = row.querySelector("td.mono"); if (valueCell) valueCell.textContent = zoneType.replace("_", "-") + (zoneInterfaces.length ? " · " + zoneInterfaces.join(", ") : " · geen interfaces") + " · User-ID " + ((item.enable_user_identification === true || item.enable_user_identification === "yes") ? "aan" : "uit"); } button.addEventListener("click", function () { openEditor(item); }); row.addEventListener("click", function (event) { if (!event.target.closest("input,button,a")) openEditor(item); }); });
    var objectList = document.querySelector(".object-list[data-edit-object]");
    var requestedObject = objectList ? objectList.dataset.editObject : "";
    if (requestedObject) {
      var requestedRow = rows.find(function (row) { var item = JSON.parse(row.dataset.object); return item.editable && item.name === requestedObject; });
      if (requestedRow) openEditor(JSON.parse(requestedRow.dataset.object));
    }
    var cancel = dialog.querySelector("[data-object-cancel]"); if (cancel) cancel.addEventListener("click", function () { dialog.close(); });
    form.addEventListener("submit", function () { addFreeformTag(); commitDynamicEntry(); syncGenericUpdates(); });
    var pickerPanel = dialog.querySelector("[data-member-picker-panel]"); var catalogNode = dialog.querySelector("[data-object-catalog]"); var catalog = catalogNode ? JSON.parse(catalogNode.textContent || "[]") : []; var pickerMode = "members"; var objectPickerSelections = new Set();
    var objectApplicationCatalog = dialog.querySelector("[data-object-application-catalog]"); var objectApplicationsLoaded = false;
    function loadObjectApplications() { if (!objectApplicationCatalog || objectApplicationsLoaded) return; objectApplicationsLoaded = true; fetch(objectApplicationCatalog.dataset.objectApplicationCatalog, {headers:{"Accept":"application/json"}}).then(function (response) { if (!response.ok) throw new Error("HTTP " + response.status); return response.json(); }).then(function (data) { var known = new Set(catalog.map(function (item) { return item.kind + "\u0000" + item.name; })); (data.items || []).forEach(function (item) { var key = "applications\u0000" + item.name; if (!known.has(key)) { known.add(key); catalog.push({name:item.name,kind:"applications"}); } }); if (pickerMode === "members" && pickerPanel && !pickerPanel.hidden) renderCatalog((pickerPanel.querySelector("[data-member-filter]").value || "").toLocaleLowerCase()); if (!data.ready && data.refreshing) { objectApplicationsLoaded = false; setTimeout(loadObjectApplications, 3000); } }).catch(function () { objectApplicationsLoaded = false; }); }
    function updateObjectPickerCount() { var count = pickerPanel && pickerPanel.querySelector("[data-object-picker-selected-count]"); if (count) count.textContent = objectPickerSelections.size; }
    function compatibleCatalogItem(item) { if (pickerMode === "dynamic" || pickerMode === "tags") return item.kind === "tags"; return item.kind !== "tags"; }
    function renderCatalog(query) { if (!pickerPanel) return; var results = pickerPanel.querySelector("[data-member-results]"); results.innerHTML = ""; var ownName = form.querySelector('[name="name"]').value; var matches = catalog.filter(function (item) { return item.name !== ownName && compatibleCatalogItem(item) && (!query || item.name.toLocaleLowerCase().includes(query)); }); matches.forEach(function (item) { var row = document.createElement("div"); row.className = "member-result" + (objectPickerSelections.has(item.name) ? " is-selected" : ""); var copy = document.createElement("div"); var strong = document.createElement("strong"); strong.textContent = item.name; var small = document.createElement("small"); small.textContent = item.kind; copy.appendChild(strong); copy.appendChild(small); var button = document.createElement("button"); button.className = "btn btn-small"; button.type = "button"; button.textContent = objectPickerSelections.has(item.name) ? "Geselecteerd" : "Selecteer"; function toggleSelection() { if (objectPickerSelections.has(item.name)) objectPickerSelections.delete(item.name); else objectPickerSelections.add(item.name); updateObjectPickerCount(); renderCatalog(query); } button.addEventListener("click", function (event) { event.stopPropagation(); toggleSelection(); }); row.addEventListener("click", toggleSelection); row.appendChild(copy); row.appendChild(button); results.appendChild(row); }); if (!matches.length) { var empty = document.createElement("div"); empty.className = "muted member-result"; empty.textContent = catalog.length ? "Geen resultaten" : "Catalogus wordt bijgewerkt; vernieuw deze pagina over enkele ogenblikken."; results.appendChild(empty); } updateObjectPickerCount(); }
    function openObjectPicker(mode) { if (!pickerPanel) return; pickerMode = mode; objectPickerSelections.clear(); pickerPanel.hidden = false; var filter = pickerPanel.querySelector("[data-member-filter]"); filter.value = ""; renderCatalog(""); if (mode === "members") loadObjectApplications(); filter.focus(); }
    var pickerOpen = dialog.querySelector("[data-member-picker-open]"); if (pickerOpen) pickerOpen.addEventListener("click", function () { openObjectPicker("members"); });
    var tagPickerOpen = dialog.querySelector("[data-tag-picker-open]"); if (tagPickerOpen) tagPickerOpen.addEventListener("click", function () { openObjectPicker("tags"); });
    var tagEntry = dialog.querySelector("[data-object-tag-entry]"); var tagAdd = dialog.querySelector("[data-object-tag-add]");
    function addFreeformTag() { if (!tagEntry) return; var values = parseTagTokens(tagEntry.value); if (!values.length) return; values.forEach(function (value) { tagSet.add(value); }); if (tagInput) tagInput.value = Array.from(tagSet).join(","); tagEntry.value = ""; renderTags(); }
    if (tagEntry) tagEntry.addEventListener("keydown", function (event) { if (event.key === "Enter" || event.key === "," || (event.key === " " && !tagQuoteOpen(tagEntry.value))) { event.preventDefault(); addFreeformTag(); } });
    if (tagAdd) tagAdd.addEventListener("click", addFreeformTag);
    if (dynamicEntry && pickerPanel) dynamicEntry.addEventListener("focus", function () { openObjectPicker("dynamic"); });
    var addObjectPickerSelected = dialog.querySelector("[data-object-picker-add-selected]"); if (addObjectPickerSelected) addObjectPickerSelected.addEventListener("click", function () { objectPickerSelections.forEach(function (name) { if (pickerMode === "dynamic") { var quoted = "'" + name.replace(/'/g, "\\'") + "'"; if (!dynamicTokens.includes(quoted)) dynamicTokens.push(quoted); } else if (pickerMode === "tags") { tagSet.add(name); } else { memberSet.add(name); } }); if (pickerMode === "dynamic") syncDynamicFilter(); else if (pickerMode === "tags") { if (tagInput) tagInput.value = Array.from(tagSet).join(","); renderTags(); } else { if (memberInput) memberInput.value = Array.from(memberSet).join(","); renderMembers(); } objectPickerSelections.clear(); updateObjectPickerCount(); pickerPanel.hidden = true; });
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
    fields.forEach(function (field) {
      var hidden = field.querySelector("[data-offline-policy-input]");
      var entry = field.querySelector("[data-offline-policy-entry]");
      var values = new Set((hidden.value || "").split(",").map(function (value) { return value.trim(); }).filter(Boolean));
      function render() {
        var container = field.querySelector("[data-offline-policy-values]"); container.innerHTML = "";
        values.forEach(function (value) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.addEventListener("click", function () { values.delete(value); hidden.value = Array.from(values).join(","); render(); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); });
        if (!values.size) { var empty = document.createElement("span"); empty.className = "muted"; empty.textContent = "Geen waarden"; container.appendChild(empty); }
      }
      function addValue(value) { var additions = field.dataset.offlinePolicyField === "tag" ? parseTagTokens(value) : [(value || "").trim()].filter(Boolean); if (!additions.length) return; additions.forEach(function (item) { values.add(item); }); hidden.value = Array.from(values).join(","); entry.value = ""; render(); }
      field._offlineAddValue = addValue;
      field._offlineValues = values;
      field.querySelector("[data-offline-policy-add]").addEventListener("click", function () { addValue(entry.value); });
      entry.addEventListener("keydown", function (event) { var tagDelimiter = field.dataset.offlinePolicyField === "tag" && (event.key === "," || (event.key === " " && !tagQuoteOpen(entry.value))); if (event.key === "Enter" || tagDelimiter) { event.preventDefault(); addValue(entry.value); } });
      render();
    });
    var offlineForm = offlineDialog && offlineDialog.querySelector("form"); if (offlineForm) offlineForm.addEventListener("submit", function () { fields.forEach(function (field) { var entry = field.querySelector("[data-offline-policy-entry]"); if (entry && entry.value.trim()) field._offlineAddValue(entry.value); }); });
    var picker = document.querySelector("[data-offline-policy-picker]");
    var catalogNode = document.querySelector("[data-offline-policy-catalog]");
    if (picker && catalogNode && fields.length) {
      var catalog = JSON.parse(catalogNode.textContent || "[]"); var activeField = null; var selected = new Set(); var currentQuery = "";
      var applicationState = document.querySelector("[data-workspace-application-catalog]"); var applicationPolls = 0;
      function updateSelectedCount() { var count = picker.querySelector("[data-policy-picker-selected-count]"); if (count) count.textContent = selected.size; }
      function renderPicker(query) {
        currentQuery = query;
        var results = picker.querySelector("[data-offline-policy-picker-results]"); results.innerHTML = "";
        var entry = activeField && activeField.querySelector("[data-offline-policy-entry]");
        var kinds = entry ? (entry.dataset.offlinePolicyKinds || "").split(/\s+/).filter(Boolean) : [];
        var candidates = catalog.filter(function (item) { return kinds.includes(item.kind); });
        if (kinds.includes("current")) { var seen = new Set(candidates.map(function (item) { return item.name; })); fields.forEach(function (field) { field._offlineValues.forEach(function (name) { if (!seen.has(name)) { seen.add(name); candidates.push({name:name,kind:"huidige configuratie"}); } }); }); }
        candidates.filter(function (item) { return !query || item.name.toLocaleLowerCase().includes(query); }).forEach(function (item) { var row = document.createElement("div"); row.className = "member-result" + (selected.has(item.name) ? " is-selected" : ""); var copy = document.createElement("div"); var strong = document.createElement("strong"); strong.textContent = item.name; var small = document.createElement("small"); small.textContent = item.kind; copy.appendChild(strong); copy.appendChild(small); var button = document.createElement("button"); button.type = "button"; button.className = "btn btn-small"; button.textContent = selected.has(item.name) ? "Geselecteerd" : "Selecteer"; button.addEventListener("click", function () { if (selected.has(item.name)) selected.delete(item.name); else selected.add(item.name); updateSelectedCount(); renderPicker(query); }); row.appendChild(copy); row.appendChild(button); results.appendChild(row); });
        if (!results.children.length) { var empty = document.createElement("div"); empty.className = "muted member-result"; empty.textContent = "Geen bestaande waarden gevonden; freeform blijft beschikbaar."; results.appendChild(empty); }
        updateSelectedCount();
      }
      function loadWorkspaceApplications() { if (!applicationState) return; var status = picker.querySelector("[data-policy-picker-status]"); if (status) status.textContent = "Application database wordt geladen…"; fetch(applicationState.dataset.workspaceApplicationCatalog, {headers:{"Accept":"application/json"}}).then(function (response) { if (!response.ok) throw new Error("HTTP " + response.status); return response.json(); }).then(function (data) { var existing = new Set(catalog.filter(function (item) { return item.kind === "applications"; }).map(function (item) { return item.name; })); (data.items || []).forEach(function (item) { if (!existing.has(item.name)) { existing.add(item.name); catalog.push(item); } }); if (status) status.textContent = data.error ? "Applicatiecatalogus kon niet worden bijgewerkt." : data.ready ? data.items.length + " applicaties beschikbaar." : data.refreshing ? "Application database wordt geladen…" : "Geen application database beschikbaar."; if (activeField && activeField.querySelector("[data-offline-policy-entry]").dataset.offlinePolicyKinds.includes("applications")) renderPicker(currentQuery); if (!data.ready && data.refreshing && applicationPolls < 40) { applicationPolls += 1; setTimeout(loadWorkspaceApplications, 3000); } }).catch(function () { if (status) status.textContent = "Applicatiecatalogus kon niet worden bijgewerkt."; }); }
      fields.forEach(function (field) { var entry = field.querySelector("[data-offline-policy-entry]"); entry.addEventListener("focus", function () { activeField = field; selected.clear(); picker.hidden = false; var status = picker.querySelector("[data-policy-picker-status]"); if (status) status.textContent = ""; var filter = picker.querySelector("[data-offline-policy-picker-filter]"); filter.value = ""; renderPicker(""); if (entry.dataset.offlinePolicyKinds.includes("applications")) { applicationPolls = 0; loadWorkspaceApplications(); } }); });
      picker.querySelector("[data-offline-policy-picker-filter]").addEventListener("input", function (event) { renderPicker(event.target.value.toLocaleLowerCase().trim()); });
      picker.querySelector("[data-offline-policy-picker-close]").addEventListener("click", function () { picker.hidden = true; });
      var addSelected = picker.querySelector("[data-policy-picker-add-selected]"); if (addSelected) addSelected.addEventListener("click", function () { if (!activeField) return; selected.forEach(function (name) { activeField._offlineAddValue(name); }); selected.clear(); updateSelectedCount(); picker.hidden = true; });
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

  function setupWorkspaceConfigurationEditor() {
    var dialog = document.querySelector("[data-config-dialog]");
    if (!dialog) return;
    var form = dialog.querySelector("[data-config-form]");
    var fieldsRoot = dialog.querySelector("[data-config-fields]");
    var tabsRoot = dialog.querySelector("[data-config-field-tabs]");
    var currentFields = [];

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

    function renderRecord(item) {
      currentFields = item.edit_fields || [];
      form.querySelector("[data-config-locator]").value = item.locator;
      dialog.querySelector("[data-config-dialog-title]").textContent = "Edit " + item.name;
      dialog.querySelector("[data-config-dialog-kind]").textContent = item.kind;
      dialog.querySelector("[data-config-dialog-owner]").textContent = item.owner;
      var duplicate = dialog.querySelector("[data-config-duplicate]"); if (duplicate) duplicate.hidden = !item.is_entry;
      tabsRoot.innerHTML = ""; fieldsRoot.innerHTML = "";
      var groups = [];
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
            var select = document.createElement("select"); booleanValues.forEach(function (value) { var option = document.createElement("option"); option.value = value; option.textContent = value; option.selected = String(field.value).trim().toLowerCase() === value; select.appendChild(option); }); field._input = select; wrapper.appendChild(select);
          } else {
            var input = field.kind === "json" || String(field.value || "").length > 180 ? document.createElement("textarea") : document.createElement("input"); input.value = field.value || ""; if (input.tagName === "TEXTAREA") input.rows = field.kind === "json" ? 10 : 4; field._input = input; wrapper.appendChild(input);
          }
          grid.appendChild(wrapper);
        });
        if (item.is_entry && index === 0) {
          var nameField = document.createElement("div"); nameField.className = "field full config-generic-field config-name-field";
          var nameLabel = document.createElement("label"); nameLabel.textContent = "Name";
          var nameInput = document.createElement("input"); nameInput.name = "name"; nameInput.required = true; nameInput.value = item.name;
          nameField.appendChild(nameLabel); nameField.appendChild(nameInput); grid.insertBefore(nameField, grid.firstChild);
        } else if (!item.is_entry && index === 0) {
          var hiddenName = document.createElement("input"); hiddenName.type = "hidden"; hiddenName.name = "name"; hiddenName.value = item.name; grid.appendChild(hiddenName);
        }
        panel.appendChild(grid); fieldsRoot.appendChild(panel);
      });
      activateGroup(groups[0]); dialog.showModal();
    }

    all("[data-config-record-edit]").forEach(function (button) { button.addEventListener("click", function () { renderRecord(JSON.parse(button.closest("[data-config-record-row]").getAttribute("data-config-record"))); }); });
    dialog.querySelector("[data-config-cancel]").addEventListener("click", function () { dialog.close(); });
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
    function updateSelection() { var selected = checks.filter(function (check) { return check.checked; }).length; if (count) count.textContent = selected; if (remove) remove.disabled = selected === 0; }
    checks.forEach(function (check) { check.addEventListener("change", updateSelection); }); updateSelection();
  }

  function setupWorkspaceObjects() {
    var dialog = document.querySelector("[data-workspace-object-dialog]");
    if (!dialog) return;
    all("[data-workspace-object]").forEach(function (button) {
      button.addEventListener("click", function () {
        var item = JSON.parse(button.getAttribute("data-workspace-object"));
        dialog.querySelector("[data-workspace-object-title]").textContent = item.name;
        dialog.querySelector("[data-workspace-object-owner]").textContent = item.owner + (item.editable ? " · lokale scope" : " · inherited, alleen-lezen");
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

  document.addEventListener("DOMContentLoaded", function () {
    setupNavigation();
    setupSidebarCollapse();
    setupConfigTree();
    setupPasswords();
    setupConfirmations();
    setupFlashes();
    setupBulkSelection();
    setupFilters();
    setupConditionalTargets();
    setupPushOptions();
    setupPolicyManagement();
    setupObjectManagement();
    setupOfflinePolicyTabs();
    setupWorkspaceConfigurationEditor();
    setupConfigPullProgress();
    setupWorkspaceObjects();
    setupWorkspaceContextLoading();
  });
})();
