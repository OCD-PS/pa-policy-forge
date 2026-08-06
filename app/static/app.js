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

    var singleDialog = document.querySelector("[data-policy-single-dialog]");
    if (singleDialog) {
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
      var policyCatalog = JSON.parse(policyCatalogNode.textContent || "[]"); var pickerTarget = null;
      var pickerKinds = {from:["zones"],to:["zones"],source:["addresses","address-groups"],destination:["addresses","address-groups"],application:["applications","application-groups","application-filters"],service:["services","service-groups"],tag:["tags"]};
      function addPickedValue(name) { if (!pickerTarget) return; if (pickerTarget.hasAttribute("data-bulk-entry")) { pickerTarget.value = name; pickerTarget.closest("[data-bulk-field]").querySelector("[data-bulk-add-button]").click(); } else { var values = pickerTarget.value.split(",").map(function (value) { return value.trim(); }).filter(Boolean); if (!values.includes(name)) values.push(name); pickerTarget.value = values.join(", "); } }
      function renderPolicyPicker(query) { var field = pickerTarget ? pickerTarget.dataset.pickerField : ""; var kinds = pickerKinds[field] || []; var results = valuePicker.querySelector("[data-policy-picker-results]"); results.innerHTML = ""; policyCatalog.filter(function (item) { return kinds.includes(item.kind) && (!query || item.name.toLocaleLowerCase().includes(query)); }).forEach(function (item) { var row = document.createElement("div"); row.className = "member-result"; var copy = document.createElement("div"); var strong = document.createElement("strong"); strong.textContent = item.name; var small = document.createElement("small"); small.textContent = item.kind; copy.appendChild(strong); copy.appendChild(small); var button = document.createElement("button"); button.className = "btn btn-small"; button.type = "button"; button.textContent = "+"; button.addEventListener("click", function () { addPickedValue(item.name); }); row.appendChild(copy); row.appendChild(button); results.appendChild(row); }); if (!results.children.length) { var empty = document.createElement("div"); empty.className = "muted member-result"; empty.textContent = "Geen bestaande waarden gevonden"; results.appendChild(empty); } }
      all("[data-picker-field]").forEach(function (input) { if (!pickerKinds[input.dataset.pickerField]) return; input.addEventListener("focus", function () { pickerTarget = input; valuePicker.hidden = false; valuePicker.querySelector("[data-policy-picker-title]").textContent = "Bestaande waarden voor " + input.dataset.pickerField; var filter = valuePicker.querySelector("[data-policy-picker-filter]"); filter.value = ""; renderPolicyPicker(""); }); });
      valuePicker.querySelector("[data-policy-picker-filter]").addEventListener("input", function (event) { renderPolicyPicker(event.target.value.toLocaleLowerCase().trim()); });
      valuePicker.querySelector("[data-policy-picker-close]").addEventListener("click", function () { valuePicker.hidden = true; });
    }

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
      if (!count) { window.alert("Selecteer minstens één policy."); return; }
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
      rows.forEach(function (row) { var button = row.querySelector("[data-object-detail]"); if (!button) return; var item = JSON.parse(row.dataset.object); button.addEventListener("click", function () { detailDialog.querySelector("[data-object-detail-title]").textContent = item.name; var body = detailDialog.querySelector("[data-object-detail-body]"); body.innerHTML = ""; Object.keys(item).sort().forEach(function (key) { var tr = document.createElement("tr"); var name = document.createElement("td"); name.textContent = key; var value = document.createElement("td"); value.className = "mono"; value.textContent = typeof item[key] === "object" ? JSON.stringify(item[key]) : item[key]; tr.appendChild(name); tr.appendChild(value); body.appendChild(tr); }); detailDialog.showModal(); }); });
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
    var dynamicInput = form.querySelector("[data-dynamic-input]"); var dynamicEntry = form.querySelector("[data-dynamic-entry]"); var dynamicTokens = [];
    function dynamicExpressionTokens(value) { return String(value || "").match(/'[^']*'|"[^"]*"|\(|\)|[^\s()]+/g) || []; }
    function renderDynamicTokens() { var container = form.querySelector("[data-dynamic-values]"); if (!container) return; container.innerHTML = ""; dynamicTokens.forEach(function (value, index) { var chip = document.createElement("span"); chip.className = "policy-value-chip"; var label = document.createElement("span"); label.textContent = value; var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "−"; remove.title = "Expressiedeel verwijderen"; remove.addEventListener("click", function () { dynamicTokens.splice(index, 1); syncDynamicFilter(); }); chip.appendChild(label); chip.appendChild(remove); container.appendChild(chip); }); }
    function syncDynamicFilter() { if (dynamicInput) dynamicInput.value = dynamicTokens.join(" "); renderDynamicTokens(); }
    function setDynamicFilter(value) { dynamicTokens = dynamicExpressionTokens(value); if (dynamicEntry) dynamicEntry.value = ""; syncDynamicFilter(); }
    function dynamicQuoteOpen(value) { var single = (value.match(/'/g) || []).length; var double = (value.match(/"/g) || []).length; return single % 2 === 1 || double % 2 === 1; }
    function commitDynamicEntry() { if (!dynamicEntry) return; var value = dynamicEntry.value.trim(); if (!value) return; dynamicTokens = dynamicTokens.concat(dynamicExpressionTokens(value)); dynamicEntry.value = ""; syncDynamicFilter(); }
    if (dynamicEntry) dynamicEntry.addEventListener("keydown", function (event) { if ((event.key === " " && !dynamicQuoteOpen(dynamicEntry.value)) || event.key === "Enter") { event.preventDefault(); commitDynamicEntry(); } });
    function setField(name, value) { var field = form.querySelector('[data-object-field="' + name + '"]'); if (!field) return; field.value = Array.isArray(value) ? value.join(", ") : (value == null ? "" : value); }
    function openEditor(item) {
      form.reset(); form.querySelector("[data-object-id]").value = item && item.id ? item.id : "";
      dialog.querySelector("[data-object-dialog-title]").textContent = (item ? "Edit " : "Add ") + document.querySelector(".object-list h2").textContent;
      setMembers([]); setDynamicFilter("");
      var zoneConfig = form.querySelector("[data-zone-current-config]");
      if (!zoneConfig && form.querySelector('[data-object-field="zone_type"]')) { zoneConfig = document.createElement("details"); zoneConfig.className = "zone-current-config field full"; zoneConfig.dataset.zoneCurrentConfig = ""; var summary = document.createElement("summary"); summary.textContent = "Volledige huidige zoneconfig"; var pre = document.createElement("pre"); pre.className = "mono"; zoneConfig.appendChild(summary); zoneConfig.appendChild(pre); form.querySelector(".form-grid").appendChild(zoneConfig); }
      if (zoneConfig) { zoneConfig.hidden = !(item && item.network); if (item && item.network) { var visibleConfig = {}; Object.keys(item).sort().forEach(function (key) { if (!["_xml", "_raw"].includes(key)) visibleConfig[key] = item[key]; }); zoneConfig.querySelector("pre").textContent = JSON.stringify(visibleConfig, null, 2); } }
      if (item) {
        setField("name", item.name); setField("description", item.description); setField("comments", item.comments); setField("tag", item.tag);
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
    var cancel = dialog.querySelector("[data-object-cancel]"); if (cancel) cancel.addEventListener("click", function () { dialog.close(); });
    form.addEventListener("submit", commitDynamicEntry);
    var pickerPanel = dialog.querySelector("[data-member-picker-panel]"); var catalogNode = dialog.querySelector("[data-object-catalog]"); var catalog = catalogNode ? JSON.parse(catalogNode.textContent || "[]") : []; var pickerMode = "members";
    function renderCatalog(query) { if (!pickerPanel) return; var results = pickerPanel.querySelector("[data-member-results]"); results.innerHTML = ""; var ownName = form.querySelector('[name="name"]').value; var matches = catalog.filter(function (item) { return item.name !== ownName && (pickerMode !== "dynamic" || item.kind === "tags") && (!query || item.name.toLocaleLowerCase().includes(query)); }); matches.forEach(function (item) { var row = document.createElement("div"); row.className = "member-result"; var copy = document.createElement("div"); var strong = document.createElement("strong"); strong.textContent = item.name; var small = document.createElement("small"); small.textContent = item.kind; copy.appendChild(strong); copy.appendChild(small); var button = document.createElement("button"); button.className = "btn btn-small"; button.type = "button"; button.textContent = pickerMode === "members" && memberSet.has(item.name) ? "Toegevoegd" : "+"; button.disabled = pickerMode === "members" && memberSet.has(item.name); button.addEventListener("click", function () { if (pickerMode === "dynamic") { var quoted = "'" + item.name.replace(/'/g, "\\'") + "'"; if (!dynamicTokens.includes(quoted)) dynamicTokens.push(quoted); syncDynamicFilter(); } else { memberSet.add(item.name); memberInput.value = Array.from(memberSet).join(","); renderMembers(); } renderCatalog((pickerPanel.querySelector("[data-member-filter]").value || "").toLocaleLowerCase()); }); row.appendChild(copy); row.appendChild(button); results.appendChild(row); }); if (!matches.length) { var empty = document.createElement("div"); empty.className = "muted member-result"; empty.textContent = catalog.length ? "Geen resultaten" : "Catalogus wordt bijgewerkt; vernieuw deze pagina over enkele ogenblikken."; results.appendChild(empty); } }
    var pickerOpen = dialog.querySelector("[data-member-picker-open]"); if (pickerOpen) pickerOpen.addEventListener("click", function () { pickerMode = "members"; pickerPanel.hidden = false; renderCatalog(""); pickerPanel.querySelector("[data-member-filter]").focus(); });
    if (dynamicEntry && pickerPanel) dynamicEntry.addEventListener("focus", function () { pickerMode = "dynamic"; pickerPanel.hidden = false; renderCatalog(""); pickerPanel.querySelector("[data-member-filter]").focus(); });
    var pickerClose = dialog.querySelector("[data-member-picker-close]"); if (pickerClose) pickerClose.addEventListener("click", function () { pickerPanel.hidden = true; });
    var memberFilter = dialog.querySelector("[data-member-filter]"); if (memberFilter) memberFilter.addEventListener("input", function () { renderCatalog(memberFilter.value.toLocaleLowerCase().trim()); });
    updateCount(); updateGroupType(); updateTimeouts();
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
    setupObjectManagement();
  });
})();
