/**
 * Secure Popup Function - acm_SecurePopUp
 * Creates a modal popup with customizable message and up to 10 buttons
 * Returns a Promise that resolves with the selected button's value
 * 
 * Usage: const result = await acm_SecurePopUp("Message", "Button1:Value1", "Button2:Value2", ...);
 */

function acm_SecurePopUp(message, ...buttonDefinitions) {
    return new Promise((resolve, reject) => {
        // Default window caption
        const WindowCaption = 'Secure Access.';
        // Input validation and security checks
        if (typeof message !== 'string' || message.trim() === '') {
            reject(new Error('Message must be a non-empty string'));
            return;
        }

        // Limit to 10 buttons for usability and security
        if (buttonDefinitions.length === 0) {
            reject(new Error('At least one button must be defined'));
            return;
        }

        if (buttonDefinitions.length > 10) {
            reject(new Error('Maximum 10 buttons allowed'));
            return;
        }
        // Parse and validate button definitions
        const buttons = [];

        for (let i = 0; i < buttonDefinitions.length; i++) {
            const buttonDef = buttonDefinitions[i];
            
            if (typeof buttonDef !== 'string') {
                reject(new Error(`Button definition ${i + 1} must be a string`));
                return;
            }

            // Parse button format "Label : Value"
            const parts = buttonDef.split(':');
            if (parts.length !== 2) {
                reject(new Error(`Invalid button format at position ${i + 1}. Use "Label : Value"`));
                return;
            }

            const label = parts[0].trim();
            const value = parts[1].trim();

            // Security: Validate label and value
            if (label === '' || value === '') {
                reject(new Error(`Button label and value cannot be empty at position ${i + 1}`));
                return;
            }

            // Prevent XSS by limiting allowed characters in labels
            if (!/^[\w\s\-.,!?()]+$/.test(label)) {
                reject(new Error(`Button label contains invalid characters at position ${i + 1}`));
                return;
            }

            buttons.push({ label, value });
        }

        // Create modal elements
        const overlay = document.createElement('div');
        const modal = document.createElement('div');
        const titleDiv = document.createElement('div');
        const messageDiv = document.createElement('div');
        const buttonsContainer = document.createElement('div');

        // Set up overlay (backdrop)
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, sans-serif;
        `;

        // Set up modal
        modal.style.cssText = `
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            min-width: 300px;
            padding: 0;
            margin: 20px;
            max-height: 80vh;
            overflow: hidden;
            animation: acmPopupFadeIn 0.2s ease-out;
        `;

        // Set up title area (use WindowCaption)
        const displayTitle = WindowCaption;
        titleDiv.style.cssText = `
            padding: 20px 24px 12px 24px;
            font-size: 18px;
            font-weight: bold;
            color: #333;
            border-bottom: 1px solid #eee;
            background: #e3f2fd;
        `;
        titleDiv.textContent = displayTitle;

        // Set up message area
        messageDiv.style.cssText = `
            padding: 16px 24px;
            font-size: 16px;
            line-height: 1.5;
            color: #333;
            word-wrap: break-word;
        `;

        // Security: Sanitize message content to prevent XSS
        messageDiv.textContent = message;

        // Set up buttons container
        buttonsContainer.style.cssText = `
            padding: 16px 24px 24px 24px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            justify-content: flex-end;
        `;

        // Create buttons
        buttons.forEach((button, index) => {
            const btn = document.createElement('button');
            btn.textContent = button.label; // Security: Use textContent to prevent XSS
            btn.setAttribute('data-value', button.value);
            btn.setAttribute('type', 'button'); // Prevent form submission
            
            btn.style.cssText = `
                background: ${index === 0 ? '#007bff' : '#6c757d'};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
                min-width: 70px;
                transition: background-color 0.2s;
            `;

            // Hover effects
            btn.addEventListener('mouseenter', () => {
                btn.style.backgroundColor = index === 0 ? '#0056b3' : '#545b62';
            });

            btn.addEventListener('mouseleave', () => {
                btn.style.backgroundColor = index === 0 ? '#007bff' : '#6c757d';
            });

            // Click handler
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const selectedValue = btn.getAttribute('data-value');
                cleanup();
                resolve(selectedValue);
            });

            buttonsContainer.appendChild(btn);
        });

        // Add CSS animation
        if (!document.getElementById('acm-popup-styles')) {
            const style = document.createElement('style');
            style.id = 'acm-popup-styles';
            style.textContent = `
                @keyframes acmPopupFadeIn {
                    from { opacity: 0; transform: scale(0.9); }
                    to { opacity: 1; transform: scale(1); }
                }
            `;
            document.head.appendChild(style);
        }

        // Cleanup function
        function cleanup() {
            if (overlay && overlay.parentNode) {
                overlay.parentNode.removeChild(overlay);
            }
            // Remove event listeners
            document.removeEventListener('keydown', handleKeydown);
            window.removeEventListener('beforeunload', handleUnload);
        }

        // Handle escape key
        function handleKeydown(e) {
            if (e.key === 'Escape') {
                e.preventDefault();
                cleanup();
                resolve(buttons[buttons.length - 1].value); // Return last button value on escape
            }
        }

        // Handle page unload
        function handleUnload() {
            cleanup();
            reject(new Error('Page unloaded'));
        }

        // Prevent overlay click from closing modal (security feature)
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                e.preventDefault();
                e.stopPropagation();
                // Optional: Add visual feedback that clicking outside doesn't close
                modal.style.animation = 'none';
                modal.offsetHeight; // Trigger reflow
                modal.style.animation = 'acmPopupShake 0.3s ease-in-out';
            }
        });

        // Add shake animation for invalid clicks
        if (!document.getElementById('acm-popup-shake-styles')) {
            const shakeStyle = document.createElement('style');
            shakeStyle.id = 'acm-popup-shake-styles';
            shakeStyle.textContent = `
                @keyframes acmPopupShake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-5px); }
                    75% { transform: translateX(5px); }
                }
            `;
            document.head.appendChild(shakeStyle);
        }

        // Assemble modal
        modal.appendChild(titleDiv);
        modal.appendChild(messageDiv);
        modal.appendChild(buttonsContainer);
        overlay.appendChild(modal);

        // Add event listeners
        document.addEventListener('keydown', handleKeydown);
        window.addEventListener('beforeunload', handleUnload);

        // Add to DOM
        document.body.appendChild(overlay);

        // Focus first button for accessibility
        setTimeout(() => {
            const firstButton = buttonsContainer.querySelector('button');
            if (firstButton) {
                firstButton.focus();
            }
        }, 100);

        // Auto-cleanup after 5 minutes to prevent memory leaks
        setTimeout(() => {
            if (overlay && overlay.parentNode) {
                cleanup();
                reject(new Error('Popup timeout'));
            }
        }, 300000);
    });
}