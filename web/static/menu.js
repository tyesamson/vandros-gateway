(function () {
  var openMenu = null;

  document.querySelectorAll("select").forEach(enhance);

  document.addEventListener("mousedown", function (event) {
    if (openMenu && !openMenu.contains(event.target)) close(openMenu);
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && openMenu) {
      var button = openMenu.querySelector(".pick-button");
      close(openMenu);
      if (button) button.focus();
    }
  });

  function enhance(select) {
    if (select.closest(".pick-menu")) return;
    var menu = document.createElement("div");
    menu.className = "pick-menu";
    select.parentNode.insertBefore(menu, select);
    menu.appendChild(select);
    select.classList.add("pick-native");
    select.tabIndex = -1;
    select.setAttribute("aria-hidden", "true");

    var button = document.createElement("button");
    button.type = "button";
    button.className = "pick-button";
    button.disabled = select.disabled;
    button.setAttribute("aria-haspopup", "listbox");
    button.setAttribute("aria-expanded", "false");
    var listId = "pick-" + Math.random().toString(36).slice(2, 10);
    button.setAttribute("aria-controls", listId);
    var label = fieldLabel(select);
    if (label) button.setAttribute("aria-label", label);
    menu.appendChild(button);

    var list = document.createElement("ul");
    list.className = "pick-list";
    list.id = listId;
    list.setAttribute("role", "listbox");
    list.hidden = true;
    menu.appendChild(list);

    var active = 0;

    function options() {
      return Array.prototype.slice.call(select.options);
    }

    function paint() {
      var items = list.children;
      var chosen = select.selectedIndex;
      for (var i = 0; i < items.length; i++) {
        items[i].classList.toggle("is-active", i === active);
        items[i].setAttribute("aria-selected", i === chosen ? "true" : "false");
      }
      if (items[active]) button.setAttribute("aria-activedescendant", items[active].id);
      var current = select.options[select.selectedIndex];
      button.textContent = current ? current.text : "";
    }

    function rebuild() {
      list.replaceChildren();
      options().forEach(function (opt, i) {
        var item = document.createElement("li");
        item.setAttribute("role", "option");
        item.id = listId + "-" + i;
        item.textContent = opt.text;
        if (opt.disabled) item.setAttribute("aria-disabled", "true");
        list.appendChild(item);
      });
      active = Math.max(0, select.selectedIndex);
      paint();
    }

    function open() {
      if (select.disabled) return;
      if (openMenu && openMenu !== menu) close(openMenu);
      list.hidden = false;
      button.setAttribute("aria-expanded", "true");
      active = Math.max(0, select.selectedIndex);
      paint();
      openMenu = menu;
    }

    function choose(index) {
      var opt = select.options[index];
      if (!opt || opt.disabled) return;
      select.selectedIndex = index;
      select.dispatchEvent(new Event("change", { bubbles: true }));
      active = index;
      paint();
      close(menu);
      button.focus();
    }

    function move(delta) {
      var next = active;
      var opts = options();
      do {
        next += delta;
      } while (opts[next] && opts[next].disabled);
      if (next < 0 || next >= opts.length) return;
      active = next;
      paint();
    }

    button.addEventListener("click", function () {
      if (list.hidden) open();
      else close(menu);
    });

    button.addEventListener("keydown", function (event) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (list.hidden) open();
        else move(event.key === "ArrowDown" ? 1 : -1);
      } else if (event.key === "Home") {
        event.preventDefault();
        if (list.hidden) open();
        active = 0;
        paint();
      } else if (event.key === "End") {
        event.preventDefault();
        if (list.hidden) open();
        active = options().length - 1;
        paint();
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        if (list.hidden) open();
        else choose(active);
      } else if (event.key === "Tab") {
        close(menu);
      }
    });

    list.addEventListener("mousemove", function (event) {
      var item = event.target.closest("[role='option']");
      if (!item || item.getAttribute("aria-disabled") === "true") return;
      active = Array.prototype.indexOf.call(list.children, item);
      paint();
    });

    list.addEventListener("mousedown", function (event) {
      var item = event.target.closest("[role='option']");
      if (!item) return;
      event.preventDefault();
      choose(Array.prototype.indexOf.call(list.children, item));
    });

    select.addEventListener("focus", function () { button.focus(); });
    select.addEventListener("change", paint);
    rebuild();
  }

  function close(menu) {
    var list = menu.querySelector(".pick-list");
    var button = menu.querySelector(".pick-button");
    if (list) list.hidden = true;
    if (button) {
      button.setAttribute("aria-expanded", "false");
      button.removeAttribute("aria-activedescendant");
    }
    if (openMenu === menu) openMenu = null;
  }

  function fieldLabel(select) {
    var label = select.closest("label");
    if (!label) return select.getAttribute("aria-label") || "";
    var copy = label.cloneNode(true);
    copy.querySelectorAll("select, input, em").forEach(function (node) { node.remove(); });
    return copy.textContent.replace(/\s+/g, " ").trim();
  }
})();
