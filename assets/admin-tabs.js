(function () {
  var root = document.querySelector('.amazing-security-admin [data-amsec-tabs]');
  if (!root) {
    return;
  }
  var buttons = root.querySelectorAll('[data-amsec-tab]');
  var panels = document.querySelectorAll('.amazing-security-admin [data-amsec-panel]');

  function show(id) {
    buttons.forEach(function (button) {
      var on = button.getAttribute('data-amsec-tab') === id;
      button.classList.toggle('is-current', on);
      button.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    panels.forEach(function (panel) {
      panel.hidden = panel.getAttribute('data-amsec-panel') !== id;
    });
  }

  buttons.forEach(function (button) {
    button.addEventListener('click', function () {
      var id = button.getAttribute('data-amsec-tab');
      show(id);
      if (window.history && window.history.replaceState) {
        window.history.replaceState(null, '', '#' + id);
      }
    });
  });

  var hash = window.location.hash.replace(/^#/, '');
  var known = Array.prototype.some.call(buttons, function (button) {
    return button.getAttribute('data-amsec-tab') === hash;
  });
  show(known ? hash : buttons[0].getAttribute('data-amsec-tab'));
}());
