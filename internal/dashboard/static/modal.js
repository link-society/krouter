/* YAML modal: fetches a manifest from the dashboard API and displays it.
   Any element carrying data-yaml-url / data-yaml-title opens it. */
(function () {
  "use strict";

  function modal() {
    return document.getElementById("yaml-modal");
  }

  async function open(title, url) {
    var response = await fetch(url, { headers: { Accept: "text/plain" } });
    if (!response.ok) {
      return;
    }

    document.getElementById("yaml-modal-title").textContent = title;

    var content = document.getElementById("yaml-modal-content");
    content.textContent = await response.text();
    content.className = "language-yaml";

    if (window.hljs) {
      content.removeAttribute("data-highlighted");
      window.hljs.highlightElement(content);
    }

    modal().classList.add("is-active");
  }

  function close() {
    modal().classList.remove("is-active");
  }

  document.addEventListener("click", function (event) {
    var closer = event.target.closest("[data-modal-close]");
    if (closer) {
      close();
      return;
    }

    var source = event.target.closest("[data-yaml-url]");
    if (source) {
      open(source.dataset.yamlTitle || "Manifest", source.dataset.yamlUrl);
    }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      close();
    }
  });

  window.krouterModal = { open: open, close: close };
})();
