/**
 * django-pow.js
 * =============
 * High-level client library for Django-POW.
 *
 * Quick start
 * -----------
 *   // 1. Load the script (or import as ES module)
 *   // 2. Call DjangoPOW.protect(formElement) once the DOM is ready.
 *
 * The library will:
 *   a) Fetch the challenge from /pow/challenge/?path=<form action>
 *   b) Spawn a Web Worker to mine the nonce
 *   c) Attach the nonce to the form submission as the X-PoW-Nonce header
 *      (works with both traditional form submits and fetch/AJAX)
 *   d) Expose progress + status via callbacks / events
 *
 * Advanced usage
 * --------------
 *   const pow = new DjangoPOW({ workerUrl: "/static/django_pow/pow_worker.js" });
 *   await pow.mine({ challenge, difficulty, username, algorithm });
 *   // pow.nonce is now set; include it in your request headers.
 */

(function (global) {
  "use strict";

  // -------------------------------------------------------------------------
  // Defaults
  // -------------------------------------------------------------------------
  const DEFAULTS = {
    workerUrl: "/static/django_pow/pow_worker.js",
    challengeEndpoint: "/pow/challenge/",
    nonceHeader: "X-PoW-Nonce",
    usernameField: "username",
    statusSelector: null,           // CSS selector for a status element
    submitSelector: '[type="submit"]',
    onProgress: null,               // function(attempts)
    onSuccess: null,                // function({ nonce, hash, attempts, durationMs })
    onError: null,                  // function(errorMessage)
  };

  // -------------------------------------------------------------------------
  // DjangoPOW class
  // -------------------------------------------------------------------------
  class DjangoPOW {
    constructor(options = {}) {
      this.config = Object.assign({}, DEFAULTS, options);
      this.nonce = null;
      this._worker = null;
    }

    // -----------------------------------------------------------------------
    // Public: mine a nonce for the given parameters
    // -----------------------------------------------------------------------
    mine({ challenge, difficulty, username, algorithm = "sha256" }) {
      return new Promise((resolve, reject) => {
        if (this._worker) {
          this._worker.terminate();
          this._worker = null;
        }

        const worker = new Worker(this.config.workerUrl);
        this._worker = worker;

        worker.postMessage({ challenge, difficulty, username, algorithm });

        worker.onmessage = (e) => {
          const data = e.data;

          if (data.progress !== undefined) {
            this._emit("progress", data.progress);
            if (typeof this.config.onProgress === "function") {
              this.config.onProgress(data.progress);
            }
            return;
          }

          worker.terminate();
          this._worker = null;

          if (data.error) {
            const msg = data.error === "timeout"
              ? `Mining timed out after ${data.attempts} attempts.`
              : `Worker error: ${data.error}`;
            if (typeof this.config.onError === "function") this.config.onError(msg);
            reject(new Error(msg));
            return;
          }

          this.nonce = data.nonce;
          if (typeof this.config.onSuccess === "function") this.config.onSuccess(data);
          resolve(data);
        };

        worker.onerror = (err) => {
          worker.terminate();
          this._worker = null;
          const msg = `Worker threw an error: ${err.message}`;
          if (typeof this.config.onError === "function") this.config.onError(msg);
          reject(new Error(msg));
        };
      });
    }

    // -----------------------------------------------------------------------
    // Public: fetch challenge from the server
    // -----------------------------------------------------------------------
    async fetchChallenge(path) {
      const url = new URL(this.config.challengeEndpoint, window.location.origin);
      if (path) url.searchParams.set("path", path);
      const res = await fetch(url.toString(), { credentials: "same-origin" });
      if (!res.ok) throw new Error(`Challenge fetch failed: ${res.status} ${res.statusText}`);
      return res.json();  // { challenge, difficulty, algorithm }
    }

    // -----------------------------------------------------------------------
    // Public: high-level — protect a <form> element automatically
    // -----------------------------------------------------------------------
    async protect(formElement) {
      if (!(formElement instanceof HTMLFormElement)) {
        throw new TypeError("protect() expects an HTMLFormElement.");
      }

      const submit = formElement.querySelector(this.config.submitSelector);
      const statusEl = this.config.statusSelector
        ? document.querySelector(this.config.statusSelector)
        : null;

      const setStatus = (msg) => { if (statusEl) statusEl.textContent = msg; };
      const disableSubmit = (v) => { if (submit) submit.disabled = v; };

      // Intercept submit
      formElement.addEventListener("submit", async (event) => {
        event.preventDefault();
        disableSubmit(true);
        setStatus("⏳ Solving proof of work…");

        try {
          const path = formElement.action
            ? new URL(formElement.action).pathname
            : window.location.pathname;

          const { challenge, difficulty, algorithm } = await this.fetchChallenge(path);

          const usernameEl = formElement.querySelector(`[name="${this.config.usernameField}"]`);
          const username = usernameEl ? usernameEl.value : "";

          setStatus(`⛏ Mining… (difficulty: ${difficulty})`);

          const result = await this.mine({ challenge, difficulty, username, algorithm });

          setStatus(`✅ Done! (${result.attempts} attempts, ${result.durationMs}ms)`);

          // Attach nonce and submit via fetch (or native submit if preferred)
          await this._submitForm(formElement, result.nonce);
        } catch (err) {
          setStatus(`❌ ${err.message}`);
          disableSubmit(false);
          console.error("[DjangoPOW]", err);
        }
      });
    }

    // -----------------------------------------------------------------------
    // Internal: submit form with the nonce header attached
    // -----------------------------------------------------------------------
    async _submitForm(formElement, nonce) {
      const formData = new FormData(formElement);
      const response = await fetch(formElement.action || window.location.href, {
        method: formElement.method || "POST",
        headers: {
          [this.config.nonceHeader]: nonce,
          "X-CSRFToken": this._getCSRF(),
        },
        body: formData,
        credentials: "same-origin",
      });

      if (response.redirected) {
        window.location.href = response.url;
        return;
      }

      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `Server responded with ${response.status}`);
      }

      // Let the caller / page handle the response (could be JSON or redirect)
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        const data = await response.json();
        this._emit("submitted", { response, data });
      } else {
        // Reload or redirect
        window.location.reload();
      }
    }

    // -----------------------------------------------------------------------
    // Internal: dispatch a CustomEvent on window
    // -----------------------------------------------------------------------
    _emit(name, detail) {
      window.dispatchEvent(new CustomEvent(`djpow:${name}`, { detail }));
    }

    // -----------------------------------------------------------------------
    // Internal: extract CSRF token
    // -----------------------------------------------------------------------
    _getCSRF() {
      const el = document.querySelector("[name=csrfmiddlewaretoken]");
      if (el) return el.value;
      const cookie = document.cookie.split(";").find(c => c.trim().startsWith("csrftoken="));
      return cookie ? cookie.split("=")[1] : "";
    }
  }

  // -------------------------------------------------------------------------
  // Auto-init via data-pow attribute
  // -------------------------------------------------------------------------
  function autoInit() {
    document.querySelectorAll("form[data-pow]").forEach((form) => {
      const options = {};
      if (form.dataset.powWorker)   options.workerUrl = form.dataset.powWorker;
      if (form.dataset.powStatus)   options.statusSelector = form.dataset.powStatus;
      if (form.dataset.powUsername) options.usernameField = form.dataset.powUsername;

      const pow = new DjangoPOW(options);
      pow.protect(form);
    });
  }

  // -------------------------------------------------------------------------
  // Expose globally
  // -------------------------------------------------------------------------
  global.DjangoPOW = DjangoPOW;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", autoInit);
  } else {
    autoInit();
  }

}(typeof window !== "undefined" ? window : this));
