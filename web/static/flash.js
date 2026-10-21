(function () {
  var flash = document.querySelector(".flash.ok");
  if (!flash) return;
  var url = new URL(location.href);
  if (url.searchParams.has("ok")) {
    url.searchParams.delete("ok");
    var query = url.searchParams.toString();
    history.replaceState(null, "", url.pathname + (query ? "?" + query : "") + url.hash);
  }
  window.setTimeout(function () {
    flash.classList.add("is-gone");
  }, 2200);
  window.setTimeout(function () {
    flash.remove();
  }, 2600);
})();
