(function () {
  var button = document.getElementById('amsec-put-examples');
  if (!button || !window.amsecTrafficExamples) {
    return;
  }
  var note = document.getElementById('amsec-example-note');
  var packs = window.amsecTrafficExamples;

  button.addEventListener('click', function () {
    var added = 0;
    var full = false;
    ['host', 'agent', 'referrer'].forEach(function (kind) {
      var box = document.getElementById(packs.fields[kind]);
      var incoming = packs[kind];
      if (!box || !Array.isArray(incoming)) {
        return;
      }
      var current = box.value.split(/\r?\n/).map(function (line) {
        return line.trim();
      }).filter(Boolean);
      incoming.forEach(function (line) {
        if (current.indexOf(line) !== -1) {
          return;
        }
        if (current.length >= 20) {
          full = true;
          return;
        }
        current.push(line);
        added += 1;
      });
      box.value = current.join('\n');
    });
    if (!note) {
      return;
    }
    note.hidden = false;
    if (added > 0) {
      note.textContent = packs.added;
      return;
    }
    note.textContent = full ? packs.full : packs.already;
  });
}());
