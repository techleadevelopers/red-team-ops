// Main JavaScript functionality for APT Red Team Dashboard

// AI Sidebar Functionality
document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('ai-sidebar');
    const toggleBtn = document.getElementById('sidebar-toggle');

    // Check if it's mobile
    function isMobile() {
        return window.innerWidth <= 768;
    }

    // Toggle sidebar (apenas no mobile)
    if (toggleBtn) {
        toggleBtn.addEventListener('click', function() {
            if (isMobile()) {
                sidebar.classList.toggle('active');

                // Animate toggle button
                const icon = this.querySelector('i');
                if (sidebar.classList.contains('active')) {
                    icon.className = 'fas fa-times';
                } else {
                    icon.className = 'fas fa-bars';
                }
            }
        });

        // Close sidebar when clicking outside (apenas no mobile)
        document.addEventListener('click', function(e) {
            if (isMobile() && !sidebar.contains(e.target) && !toggleBtn.contains(e.target)) {
                sidebar.classList.remove('active');
                if (toggleBtn.querySelector('i')) {
                    toggleBtn.querySelector('i').className = 'fas fa-bars';
                }
            }
        });
    }

    // Ajustar sidebar no resize
    window.addEventListener('resize', function() {
        if (!isMobile()) {
            sidebar.classList.remove('active');
            if (toggleBtn && toggleBtn.querySelector('i')) {
                toggleBtn.querySelector('i').className = 'fas fa-bars';
            }
        }
    });

    // Update AI stats
    setInterval(updateAIStats, 3000);
});

function updateAIStats() {
    const attacksEl = document.getElementById('ai-attacks');
    const learningEl = document.getElementById('learning-rate');

    if (attacksEl) {
        const currentAttacks = parseInt(attacksEl.textContent);
        attacksEl.textContent = currentAttacks + Math.floor(Math.random() * 5) + 1;
    }

    if (learningEl) {
        const rate = (98 + Math.random() * 2).toFixed(1);
        learningEl.textContent = rate + '%';
    }
}

function aiFunction(type) {
    const functions = {
        'threat-intel': 'AI Threat Intelligence analyzing global threat landscape...',
        'auto-exploit': 'AI Auto-Exploitation scanning for vulnerabilities...',
        'payload-gen': 'AI Payload Generator creating custom exploits...',
        'evasion': 'AI Evasion Techniques bypassing detection systems...',
        'behavior-analysis': 'AI Behavior Analysis studying target patterns...',
        'pattern-recognition': 'AI Pattern Recognition identifying attack vectors...',
        'adaptive-learning': 'AI Adaptive Learning updating attack strategies...',
        'neural-fuzzing': 'AI Neural Fuzzing discovering zero-day exploits...',
        'live-scanner': 'AI Live Scanner monitoring network traffic...',
        'vulnerability-prediction': 'AI Vulnerability Prediction forecasting security flaws...',
        'traffic-analysis': 'AI Traffic Analysis detecting anomalies...',
        'anomaly-detection': 'AI Anomaly Detection identifying suspicious behavior...',
        'ai-phishing': 'AI Phishing Generator creating targeted campaigns...',
        'deepfake-gen': 'AI DeepFake Generator creating synthetic media...',
        'voice-cloning': 'AI Voice Cloning synthesizing target voices...',
        'social-engineering': 'AI Social Engineering analyzing human behavior...'
    };

    showNotification(functions[type] || 'AI Function executing...', 'info');

    // Simulate AI processing
    setTimeout(() => {
        showNotification(`${type.replace('-', ' ').toUpperCase()} completed successfully!`, 'success');
    }, 2000 + Math.random() * 3000);
}

function emergencyAI() {
    showNotification('AI EMERGENCY STOP ACTIVATED!', 'error');
    
    // Visual feedback
    const emergencyBtn = document.querySelector('.ai-emergency-btn');
    const statusDot = document.querySelector('.ai-status-dot');
    const statusText = document.querySelector('.ai-status-indicator span');
    
    emergencyBtn.style.background = 'linear-gradient(45deg, #ff4444, #cc0000)';
    statusDot.style.background = '#ff4444';
    statusDot.classList.remove('operational');
    statusText.textContent = 'AI STATUS: EMERGENCY STOP';
    
    // Simulate emergency shutdown
    setTimeout(() => {
        showNotification('All AI processes safely terminated.', 'success');
        emergencyBtn.style.background = 'linear-gradient(45deg, #ff0040, #cc0033)';
        statusDot.style.background = 'var(--success-color)';
        statusDot.classList.add('operational');
        statusText.textContent = 'AI STATUS: OPERATIONAL';
    }, 3000);
}

// New AI Operations function
function executeAIOperation(operation) {
    const operations = {
        'threat-scan': {
            name: 'Threat Intelligence Scan',
            steps: [
                'Connecting to threat intelligence feeds...',
                'Analyzing global threat landscape...',
                'Processing IOCs and TTPs...',
                'Generating threat assessment report...'
            ]
        },
        'vuln-discovery': {
            name: 'Vulnerability Discovery',
            steps: [
                'Initializing neural vulnerability scanner...',
                'Analyzing target attack surface...',
                'Running ML-based exploit detection...',
                'Cataloging discovered vulnerabilities...'
            ]
        },
        'behavior-analysis': {
            name: 'Behavior Analysis',
            steps: [
                'Collecting behavioral patterns...',
                'Running machine learning analysis...',
                'Identifying anomalous activities...',
                'Generating behavioral profile...'
            ]
        },
        'pattern-recognition': {
            name: 'Pattern Recognition',
            steps: [
                'Analyzing network traffic patterns...',
                'Identifying attack signatures...',
                'Running deep learning models...',
                'Updating pattern database...'
            ]
        },
        'payload-gen': {
            name: 'AI Payload Generator',
            steps: [
                'Analyzing target environment...',
                'Generating custom payloads...',
                'Optimizing evasion techniques...',
                'Testing payload effectiveness...'
            ]
        },
        'evasion-tech': {
            name: 'Evasion Techniques',
            steps: [
                'Scanning defense mechanisms...',
                'Generating evasion strategies...',
                'Testing bypass techniques...',
                'Updating evasion database...'
            ]
        },
        'neural-fuzzing': {
            name: 'Neural Fuzzing',
            steps: [
                'Initializing neural fuzzer...',
                'Generating intelligent test cases...',
                'Running automated fuzz tests...',
                'Analyzing crash reports...'
            ]
        },
        'adaptive-learning': {
            name: 'Adaptive Learning',
            steps: [
                'Collecting new attack data...',
                'Training neural networks...',
                'Updating ML models...',
                'Validating model accuracy...'
            ]
        }
    };
    
    const op = operations[operation];
    if (!op) return;
    
    showNotification(`Executing ${op.name}...`, 'info');
    
    // Simulate progressive execution
    let stepIndex = 0;
    const interval = setInterval(() => {
        if (stepIndex < op.steps.length) {
            showNotification(op.steps[stepIndex], 'info', 2000);
            stepIndex++;
        } else {
            clearInterval(interval);
            showNotification(`${op.name} completed successfully!`, 'success');
            
            // Update AI stats
            updateAIStatsAfterOperation(operation);
        }
    }, 1500);
}

function updateAIStatsAfterOperation(operation) {
    // Update stats based on operation type
    const attacksEl = document.getElementById('ai-attacks');
    const learningEl = document.getElementById('learning-rate');
    const networksEl = document.getElementById('neural-networks');
    const exploitsEl = document.getElementById('auto-exploits');
    
    if (attacksEl) {
        const current = parseInt(attacksEl.textContent);
        const newValue = current + Math.floor(Math.random() * 10) + 1;
        animateCounter(attacksEl, newValue);
    }
    
    if (learningEl && ['adaptive-learning', 'neural-fuzzing'].includes(operation)) {
        const rate = (98 + Math.random() * 2).toFixed(1);
        learningEl.textContent = rate + '%';
    }
    
    if (exploitsEl && ['payload-gen', 'evasion-tech'].includes(operation)) {
        const current = parseInt(exploitsEl.textContent);
        const newValue = current + Math.floor(Math.random() * 5) + 1;
        animateCounter(exploitsEl, newValue);
    }
}

function animateCounter(element, targetValue) {
    const startValue = parseInt(element.textContent);
    const duration = 1000;
    const startTime = performance.now();
    
    function updateCounter(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const currentValue = Math.floor(startValue + (targetValue - startValue) * progress);
        
        element.textContent = currentValue;
        
        if (progress < 1) {
            requestAnimationFrame(updateCounter);
        }
    }
    
    requestAnimationFrame(updateCounter);
}

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeAnimations();
    initializeNotifications();
    startMatrixEffect();

    // Auto-refresh status every 5 seconds
    setInterval(updateDashboardStatus, 5000);
});

// GSAP Animations
function initializeAnimations() {
    // Animate module cards on load
    gsap.from('.module-card', {
        duration: 0.8,
        y: 50,
        opacity: 0,
        stagger: 0.1,
        ease: 'power2.out'
    });

    // Animate stats cards
    gsap.from('.stat-card', {
        duration: 0.6,
        scale: 0.8,
        opacity: 0,
        stagger: 0.1,
        ease: 'back.out(1.7)'
    });
    // Animate stats cards with existence check
    const statCards = document.querySelectorAll(".stat-card");
    if (statCards.length > 0) {
        gsap.from(".stat-card", {
            duration: 0.8,
            y: -50,
            opacity: 0,
            stagger: 0.2,
            ease: "power2.out"
        });
    }

    // Animate module cards with existence check
    const moduleCards = document.querySelectorAll(".module-card");
    if (moduleCards.length > 0) {
        gsap.from(".module-card", {
            duration: 1,
            scale: 0.8,
            opacity: 0,
            stagger: 0.15,
            ease: "back.out(1.7)"
        });
    }

    // Continuous glow animation for important elements
    gsap.to('.nav-brand i', {
        duration: 2,
        textShadow: '0 0 30px rgba(255, 0, 64, 0.8)',
        repeat: -1,
        yoyo: true,
        ease: 'power2.inOut'
    });
}

// Matrix-style background effect
function startMatrixEffect() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.zIndex = '-2';
    canvas.style.opacity = '0.1';

    document.body.appendChild(canvas);

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charArray = chars.split('');

    const fontSize = 14;
    const columns = canvas.width / fontSize;

    const drops = [];
    for (let x = 0; x < columns; x++) {
        drops[x] = 1;
    }

    function draw() {
        ctx.fillStyle = 'rgba(10, 10, 10, 0.04)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = '#ff0040';
        ctx.font = fontSize + 'px monospace';

        for (let i = 0; i < drops.length; i++) {
            const text = charArray[Math.floor(Math.random() * charArray.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);

            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    setInterval(draw, 50);

    // Resize handler
    window.addEventListener('resize', function() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// Notification system
function initializeNotifications() {
    const container = document.getElementById('notification-container');
    if (!container) {
        const notifContainer = document.createElement('div');
        notifContainer.id = 'notification-container';
        notifContainer.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 10px;
        `;
        document.body.appendChild(notifContainer);
    }
}

function showNotification(message, type = 'info', duration = 5000) {
    const container = document.getElementById('notification-container');

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.style.cssText = `
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-left: 4px solid var(--${type === 'success' ? 'success-color' : type === 'error' ? 'error-color' : 'primary-red'});
        padding: 1rem;
        border-radius: 8px;
        color: var(--text-primary);
        font-family: var(--font-mono);
        font-size: 0.9rem;
        max-width: 350px;
        box-shadow: 0 10px 20px rgba(0, 0, 0, 0.3);
        transform: translateX(100%);
        transition: transform 0.3s ease;
    `;

    notification.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" style="
                background: none;
                border: none;
                color: var(--text-muted);
                cursor: pointer;
                font-size: 1.2rem;
                padding: 0;
                margin-left: 1rem;
            ">&times;</button>
        </div>
    `;

    container.appendChild(notification);

    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 10);

    // Auto remove
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 300);
    }, duration);
}

// Dashboard status updates
function updateDashboardStatus() {
    // Simulate real-time data changes
    const stats = ['active-attacks', 'completed-attacks', 'compromised-targets'];

    stats.forEach(stat => {
        const element = document.getElementById(stat);
        if (element && Math.random() > 0.7) {
            const currentValue = parseInt(element.textContent) || 0;
            const newValue = currentValue + Math.floor(Math.random() * 3);

            // Animate number change
            gsap.to(element, {
                duration: 0.5,
                textContent: newValue,
                roundProps: 'textContent',
                ease: 'power2.out'
            });

            // Add glow effect
            gsap.to(element.parentElement, {
                duration: 0.3,
                boxShadow: '0 0 20px rgba(0, 255, 136, 0.5)',
                yoyo: true,
                repeat: 1,
                ease: 'power2.inOut'
            });
        }
    });
}

// Execute attack with visual feedback
function executeAttack(module, attack) {
    const button = event.target;
    const originalContent = button.innerHTML;

    // Show loading state
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    button.disabled = true;

    // Add visual feedback to module card
    const moduleCard = button.closest('.module-card');
    gsap.to(moduleCard, {
        duration: 0.3,
        borderColor: '#ffaa00',
        boxShadow: '0 0 30px rgba(255, 170, 0, 0.5)',
        yoyo: true,
        repeat: 3
    });

    // Simulate attack execution
    setTimeout(() => {
        button.innerHTML = originalContent;
        button.disabled = false;

        // Success feedback
        gsap.to(moduleCard, {
            duration: 0.5,
            borderColor: 'var(--success-color)',
            boxShadow: '0 0 30px rgba(0, 255, 136, 0.5)'
        });

        showNotification(`Attack "${attack}" executed successfully!`, 'success');

        // Reset border after 2 seconds
        setTimeout(() => {
            gsap.to(moduleCard, {
                duration: 0.5,
                borderColor: 'var(--border-color)',
                boxShadow: 'none'
            });
        }, 2000);

    }, 2000 + Math.random() * 3000);
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl + T for terminal
    if (e.ctrlKey && e.key === 't') {
        e.preventDefault();
        window.location.href = '/terminal';
    }

    // Ctrl + H for home/dashboard
    if (e.ctrlKey && e.key === 'h') {
        e.preventDefault();
        window.location.href = '/';
    }

    // Escape to close modals
    if (e.key === 'Escape') {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            if (modal.style.display !== 'none') {
                modal.style.display = 'none';
            }
        });
    }
});

// Easter egg: Konami code
let konamiCode = [];
const konamiSequence = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight', 'KeyB', 'KeyA'];

document.addEventListener('keydown', function(e) {
    konamiCode.push(e.code);
    if (konamiCode.length > konamiSequence.length) {
        konamiCode.shift();
    }

    if (JSON.stringify(konamiCode) === JSON.stringify(konamiSequence)) {
        activateMatrixMode();
        konamiCode = [];
    }
});

function activateMatrixMode() {
    showNotification('MATRIX MODE ACTIVATED - Welcome to the real world, Neo.', 'success', 10000);

    // Enhanced matrix effect
    document.body.style.filter = 'hue-rotate(120deg)';
    document.documentElement.style.setProperty('--primary-red', '#00ff41');

    // Reset after 10 seconds
    setTimeout(() => {
        document.body.style.filter = '';
        document.documentElement.style.setProperty('--primary-red', '#ff0040');
        showNotification('Back to reality...', 'info');
    }, 10000);
}

// Performance monitoring
function monitorPerformance() {
    if ('performance' in window) {
        const navigation = performance.getEntriesByType('navigation')[0];
        if (navigation.loadEventEnd - navigation.loadEventStart > 3000) {
            console.warn('Slow page load detected');
        }
    }
}

// Initialize performance monitoring
window.addEventListener('load', monitorPerformance);

// Menu toggle functionality
function toggleMenuSection(element) {
    const menuSection = element.parentElement;
    const menuItems = menuSection.querySelector('.menu-items');
    
    menuSection.classList.toggle('collapsed');
    
    if (menuSection.classList.contains('collapsed')) {
        menuItems.style.maxHeight = '0px';
    } else {
        menuItems.style.maxHeight = '500px';
    }
}

// Export functions for global use
window.executeAttack = executeAttack;
window.showNotification = showNotification;
window.toggleMenuSection = toggleMenuSection;