(function () {
  var all = document.querySelector("[data-select-all]");
  if (!all) return;
  function boxes() {
    return document.querySelectorAll('input[name="file"]');
  }
  all.addEventListener("change", function () {
    boxes().forEach(function (box) { box.checked = all.checked; });
  });
  document.addEventListener("change", function (event) {
    if (!event.target || event.target.name !== "file") return;
    var list = boxes();
    var checked = 0;
    list.forEach(function (box) { if (box.checked) checked++; });
    all.checked = list.length > 0 && checked === list.length;
    all.indeterminate = checked > 0 && checked < list.length;
  });
})();
