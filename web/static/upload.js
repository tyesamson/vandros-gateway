(function () {
  var zone = document.querySelector("[data-upload]");
  if (!zone) return;
  var url = zone.getAttribute("data-upload");
  var csrf = zone.getAttribute("data-csrf");
  var label = zone.querySelector("p");
  var depth = 0;
  var busy = false;

  function draggingFiles(event) {
    var types = event.dataTransfer && event.dataTransfer.types;
    if (!types) return false;
    for (var i = 0; i < types.length; i++) {
      if (types[i] === "Files") return true;
    }
    return false;
  }

  function show(text) {
    if (label) label.textContent = text;
    zone.hidden = false;
  }

  function hide() {
    zone.hidden = true;
    if (label) label.textContent = "Drop to upload";
  }

  window.addEventListener("dragenter", function (event) {
    if (busy || !draggingFiles(event)) return;
    event.preventDefault();
    depth++;
    show("Drop to upload");
  });

  window.addEventListener("dragover", function (event) {
    if (busy || !draggingFiles(event)) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
  });

  window.addEventListener("dragleave", function (event) {
    if (busy || !draggingFiles(event)) return;
    depth--;
    if (depth <= 0) {
      depth = 0;
      hide();
    }
  });

  window.addEventListener("drop", function (event) {
    if (busy || !draggingFiles(event)) return;
    event.preventDefault();
    depth = 0;
    var dropped = filesFrom(event.dataTransfer);
    if (dropped.files.length === 0) {
      show(dropped.folders ? "Drop files, not a folder" : "Drop to upload");
      window.setTimeout(hide, 1600);
      return;
    }
    busy = true;
    send(dropped.files, 0, "");
  });

  function filesFrom(transfer) {
    var files = [];
    var folders = 0;
    var items = transfer.items;
    if (items && items.length) {
      for (var i = 0; i < items.length; i++) {
        var entry = items[i].webkitGetAsEntry && items[i].webkitGetAsEntry();
        if (entry && entry.isDirectory) {
          folders++;
          continue;
        }
        var file = items[i].getAsFile && items[i].getAsFile();
        if (file) files.push(file);
      }
      return { files: files, folders: folders };
    }
    return { files: Array.prototype.slice.call(transfer.files || []), folders: 0 };
  }

  function send(files, index, problem) {
    if (index >= files.length) {
      var folder = location.pathname;
      if (problem) location.assign(folder + "?err=" + encodeURIComponent(problem));
      else location.assign(folder + "?ok=uploaded");
      return;
    }
    show("Uploading " + (index + 1) + " of " + files.length);
    var body = new FormData();
    body.append("csrf", csrf);
    body.append("file", files[index], files[index].name);
    fetch(url, { method: "POST", body: body, credentials: "same-origin" }).then(function (res) {
      var next = problem;
      var failed = new URL(res.url, location.origin).searchParams.get("err");
      if (res.status === 404) failed = failed || "name";
      if (!res.ok && !failed) failed = "upload";
      if (failed && !next) next = failed;
      send(files, index + 1, next);
    }).catch(function () {
      send(files, index + 1, problem || "upload");
    });
  }
})();
