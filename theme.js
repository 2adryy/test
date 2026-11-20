// Dark / light mode for both SecureChat pages.
// Loaded in <head> WITHOUT "defer" so the theme is applied before the page is drawn
// (no white flash in dark mode). It is a separate file because the Content-Security-Policy
// forbids inline scripts.
"use strict";

const THEME_KEY = "securechat-theme";

function savedTheme() {
  try {
    return localStorage.getItem(THEME_KEY);   // may throw in private windows
  } catch {
    return null;
  }
}

function systemTheme() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  for (const btn of document.querySelectorAll(".theme-toggle")) {
    const dark = theme === "dark";
    btn.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
    btn.setAttribute("aria-pressed", String(dark));
    btn.title = dark ? "Light mode" : "Dark mode";
  }
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
    // storage blocked: the choice simply lasts until the page is closed
  }
}

applyTheme(savedTheme() || systemTheme());   // first visit follows the computer's setting

document.addEventListener("DOMContentLoaded", () => {
  applyTheme(document.documentElement.dataset.theme);
  for (const btn of document.querySelectorAll(".theme-toggle")) btn.addEventListener("click", toggleTheme);
});
