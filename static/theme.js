/**
 * =============================================================================
 * SecureSync – Multi Detection System
 * File: static/theme.js
 * Description: Client-side appearance switcher supporting Light, Dark, and System
 *              modes with localStorage persistence, instant zero-FOUC initialization,
 *              live OS preference synchronization, and multi-tab state management.
 * =============================================================================
 */

(function () {
    'use strict';

    const STORAGE_KEY = 'securesync_theme';

    /**
     * Resolves the current theme setting ('light' | 'dark' | 'system').
     * Defaults to 'system' if unset.
     */
    function getStoredSetting() {
        try {
            return localStorage.getItem(STORAGE_KEY) || 'system';
        } catch (e) {
            return 'system';
        }
    }

    /**
     * Resolves the actual theme to render based on user setting and OS preferences.
     */
    function resolveTheme(setting) {
        if (setting === 'light' || setting === 'dark') {
            return setting;
        }
        // 'system' mode: inspect OS preference
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        return prefersDark ? 'dark' : 'light';
    }

    /**
     * Applies the theme to the <html> root element and updates switcher UI controls.
     */
    function applyTheme(setting) {
        const resolved = resolveTheme(setting);
        const root = document.documentElement;

        root.setAttribute('data-theme', resolved);
        root.setAttribute('data-theme-setting', setting);

        // Update all theme switcher buttons on the page
        const buttons = document.querySelectorAll('.theme-btn');
        buttons.forEach((btn) => {
            const val = btn.getAttribute('data-theme-val');
            if (val === setting) {
                btn.classList.add('active');
                btn.setAttribute('aria-pressed', 'true');
            } else {
                btn.classList.remove('active');
                btn.setAttribute('aria-pressed', 'false');
            }
        });

        // Also update radio inputs if present (e.g. in account settings)
        const radios = document.querySelectorAll('input[name="theme-preference"]');
        radios.forEach((radio) => {
            radio.checked = radio.value === setting;
        });
    }

    /**
     * Sets a new theme preference, saves to localStorage, and updates UI.
     */
    function setTheme(setting) {
        try {
            localStorage.setItem(STORAGE_KEY, setting);
        } catch (e) {
            console.warn('SecureSync: Unable to persist theme to localStorage', e);
        }
        applyTheme(setting);
    }

    // Expose to window for external scripting or debugging
    window.SecureSyncTheme = {
        getSetting: getStoredSetting,
        setTheme: setTheme,
        applyTheme: applyTheme
    };

    // Apply immediately during script parse to avoid FOUC
    applyTheme(getStoredSetting());

    // When DOM is fully ready, wire up event listeners
    document.addEventListener('DOMContentLoaded', () => {
        applyTheme(getStoredSetting());

        // Delegate clicks on any theme buttons
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('.theme-btn');
            if (btn) {
                e.preventDefault();
                const val = btn.getAttribute('data-theme-val');
                if (val && ['light', 'dark', 'system'].includes(val)) {
                    setTheme(val);
                }
            }
        });

        // Listen for radio button changes if present in settings
        document.addEventListener('change', (e) => {
            if (e.target && e.target.name === 'theme-preference') {
                const val = e.target.value;
                if (val && ['light', 'dark', 'system'].includes(val)) {
                    setTheme(val);
                }
            }
        });
    });

    // Listen to live OS dark/light mode switches when System mode is active
    if (window.matchMedia) {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        const handleMediaChange = () => {
            if (getStoredSetting() === 'system') {
                applyTheme('system');
            }
        };

        if (mediaQuery.addEventListener) {
            mediaQuery.addEventListener('change', handleMediaChange);
        } else if (mediaQuery.addListener) {
            mediaQuery.addListener(handleMediaChange);
        }
    }

    // Synchronize theme across multiple browser tabs
    window.addEventListener('storage', (e) => {
        if (e.key === STORAGE_KEY) {
            applyTheme(e.newValue || 'system');
        }
    });
})();
