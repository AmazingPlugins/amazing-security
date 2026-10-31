(function () {
  var root = document.querySelector('.amsec-security-scanner-admin [data-amsec-tabs]');
  if (!root) {
    return;
  }
  var buttons = root.querySelectorAll('[data-amsec-tab]');
  var panels = document.querySelectorAll('.amsec-security-scanner-admin [data-amsec-panel]');

  function show(id) {
    buttons.forEach(function (button) {
      var on = button.getAttribute('data-amsec-tab') === id;
      button.classList.toggle('is-current', on);
      button.setAttribute('aria-selected', on ? 'true' : 'false');
      button.tabIndex = on ? 0 : -1;
    });
    panels.forEach(function (panel) {
      panel.hidden = panel.getAttribute('data-amsec-panel') !== id;
    });
  }

  function select(button) {
    var id = button.getAttribute('data-amsec-tab');
    show(id);
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, '', '#' + id);
    }
  }

  // WAI-ARIA tabs: arrows move between tabs, Home and End jump to the ends.
  var keys = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
  buttons.forEach(function (button, index) {
    button.addEventListener('click', function () {
      select(button);
    });
    button.addEventListener('keydown', function (event) {
      var next = null;
      if (keys[event.key]) {
        next = (index + keys[event.key] + buttons.length) % buttons.length;
      } else if (event.key === 'Home') {
        next = 0;
      } else if (event.key === 'End') {
        next = buttons.length - 1;
      }
      if (next === null) {
        return;
      }
      event.preventDefault();
      select(buttons[next]);
      buttons[next].focus();
    });
  });

  var hash = window.location.hash.replace(/^#/, '');
  var known = Array.prototype.some.call(buttons, function (button) {
    return button.getAttribute('data-amsec-tab') === hash;
  });
  show(known ? hash : buttons[0].getAttribute('data-amsec-tab'));
}());
