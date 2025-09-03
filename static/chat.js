marked.setOptions({
  highlight: function(code, lang) {
    if (lang && hljs.getLanguage(lang)) {
      return hljs.highlight(code, { language: lang }).value;
    }
    return hljs.highlightAuto(code).value;
  },
  langPrefix: 'hljs language-',
  breaks: true
});

document.addEventListener('DOMContentLoaded', function() {
  hljs.highlightAll();
  addCopyButtonsToCodeBlocks();
});

// ----- copy button helper (unchanged behavior) -----
function addCopyButtonsToCodeBlocks() {
  document.querySelectorAll('.bot-bubble pre').forEach((preBlock) => {
    if (preBlock.parentElement.classList.contains('code-block-wrapper')) return;

    const codeEl = preBlock.querySelector('code');
    if (!codeEl) return;

    const langClass = [...codeEl.classList].find(cls => cls.startsWith('language-'));
    const lang = langClass ? langClass.replace('language-', '') : 'code';

    const wrapper = document.createElement('div');
    wrapper.className = 'code-block-wrapper';

    const label = document.createElement('div');
    label.className = 'code-lang-label';
    label.textContent = lang.toUpperCase();

    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.title = 'Copy code';
    copyBtn.innerHTML = '<i class="fas fa-copy"></i>';

    copyBtn.onclick = () => {
      navigator.clipboard.writeText(codeEl.innerText).then(() => {
        copyBtn.innerHTML = '<i class="fas fa-check"></i>';
        setTimeout(() => {
          copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
        }, 1200);
      });
    };

    preBlock.parentNode.replaceChild(wrapper, preBlock);
    wrapper.appendChild(label);
    wrapper.appendChild(copyBtn);
    wrapper.appendChild(preBlock);
  });
}

// ----- helper: escape HTML -----
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ----- helper: parse various timestamp formats -> Date object -----
function parseTimestampToDate(ts) {
  if (!ts && ts !== 0) return null;

  // number (epoch ms)
  if (typeof ts === 'number') return new Date(ts);

  // numeric-string epoch ms
  if (typeof ts === 'string' && /^\d{10,}$/.test(ts)) {
    // if it's seconds (10 digits) convert to ms
    if (ts.length === 10) return new Date(Number(ts) * 1000);
    return new Date(Number(ts));
  }

  // ISO string or other date string
  if (typeof ts === 'string') {
    const d = new Date(ts);
    if (!isNaN(d.getTime())) return d;
  }

  // Firestore-like object { seconds:..., nanoseconds:... }
  if (typeof ts === 'object' && ts !== null) {
    if ('seconds' in ts) {
      return new Date(Number(ts.seconds) * 1000 + (ts.nanoseconds ? Math.round(ts.nanoseconds / 1000000) : 0));
    }
    // also accept {seconds: "..."} string
    if ('seconds' in ts && typeof ts.seconds === 'string') {
      return new Date(Number(ts.seconds) * 1000);
    }
  }

  return null;
}

// ----- helper: format to user's local string -----
function formatTimestampForDisplay(ts) {
  const d = parseTimestampToDate(ts);
  if (!d) return '';
  return d.toLocaleString(); // browser local time
}

// ----- add message to DOM (will format timestamp) -----
function addChatMessage(sender, message, timestamp) {
  const chatWindow = document.getElementById('ajax-chat-messages');
  if (!chatWindow) return;

  // Normalize timestamp for display: accept ISO, epoch-ms, Firestore object, or already formatted string
  let tsDisplay = '';
  if (timestamp) {
    // if timestamp is already human readable (contains spaces or commas) treat as display string fallback
    if (typeof timestamp === 'string' && /[A-Za-z, ]/.test(timestamp) && !/^\d{4}-\d{2}-\d{2}T/.test(timestamp)) {
      tsDisplay = timestamp;
    } else {
      tsDisplay = formatTimestampForDisplay(timestamp);
    }
  }

  let msgHtml = '';

  if (sender === 'bot') {
    const htmlMsg = (typeof marked !== 'undefined') ? marked.parse(message) : escapeHtml(message);
    msgHtml = `<div class="chat-message bot-message">
      <div class="message-row">
        <div class="avatar-col"><div class="avatar-label">ESB</div></div>
        <div class="message-bubble bot-bubble">
          <div class="bot-response">${htmlMsg}</div>
          <div class="timestamp">${escapeHtml(tsDisplay)}</div>
        </div>
      </div>
      <div class="button-row">
        <button class="icon-btn copy-button" title="Copy"><i class="fas fa-copy"></i></button>
        <button class="icon-btn speak-button" title="Speak"><i class="fas fa-volume-up"></i></button>
      </div>
    </div>`;
  } else {
    // user avatar: profile picture or initials
    if (!window.isInitials && window.profileAvatar) {
      msgHtml = `<div class="chat-message user-message">
        <div class="message-row">
          <div class="message-bubble user-bubble">${escapeHtml(message)}<div class="timestamp">${escapeHtml(tsDisplay)}</div></div>
          <div class="avatar-col"><img class="user-avatar" src="${escapeHtml(window.profileAvatar)}" alt="User Avatar"></div>
        </div>
        <div class="button-row">
          <button class="icon-btn delete-message-btn" data-message-index="-1" data-session-id="${escapeHtml(chatSessionId)}" title="Delete"><i class="fas fa-trash"></i></button>
        </div>
      </div>`;
    } else {
      const initial = (window.username && window.username.length) ? window.username.trim()[0].toUpperCase() : 'U';
      msgHtml = `<div class="chat-message user-message">
        <div class="message-row">
          <div class="message-bubble user-bubble">${escapeHtml(message)}<div class="timestamp">${escapeHtml(tsDisplay)}</div></div>
          <div class="avatar-col"><div class="avatar-label">${escapeHtml(initial)}</div></div>
        </div>
        <div class="button-row">
          <button class="icon-btn delete-message-btn" data-message-index="-1" data-session-id="${escapeHtml(chatSessionId)}" title="Delete"><i class="fas fa-trash"></i></button>
        </div>
      </div>`;
    }
  }

  chatWindow.insertAdjacentHTML('beforeend', msgHtml);
  if (typeof hljs !== 'undefined') hljs.highlightAll();
  addCopyButtonsToCodeBlocks();

  // scroll to bottom
  setTimeout(() => {
    const anchor = document.getElementById('scroll-anchor');
    if (anchor) anchor.scrollIntoView({ behavior: 'smooth' });
  }, 80);
}

// ----- render authoritative chat_history returned by server -----
function renderChatHistoryFromServer(chat_history) {
  const chatWindow = document.getElementById('ajax-chat-messages');
  if (!chatWindow) return;
  chatWindow.innerHTML = '';

  for (const msg of chat_history) {
    // prefer numeric timestamp_ms, fall back to ISO 'timestamp', else raw timestamp
    const tsValue = (msg.timestamp_ms && !isNaN(Number(msg.timestamp_ms))) ? Number(msg.timestamp_ms) : (msg.timestamp || msg.timestamp);
    addChatMessage(msg.sender, msg.message, tsValue);
  }

  if (typeof hljs !== 'undefined') hljs.highlightAll();
  addCopyButtonsToCodeBlocks();
}

// ----------------- main logic -----------------
const chatSessionId = "{{ chat_session_id }}"; // keep this as template-injected

// AJAX form submit (use ISO for optimistic messages; server authoritative chat_history preferred)
document.getElementById('chatForm').addEventListener('submit', function(e) {
  e.preventDefault();
  const textarea = document.getElementById('chatInput');
  const msg = textarea.value.trim();
  if (!msg) return;
  textarea.value = '';

  // optimistic local show: use ISO so server/saved values are comparable
  addChatMessage('user', msg, new Date().toISOString());

  fetch('/ajax/chat/send', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      chat_session_id: chatSessionId,
      message: msg
    })
  })
  .then(resp => resp.json())
  .then(data => {
    // If server returned an authoritative chat_history, render it (preferred)
    if (data.chat_history) {
      renderChatHistoryFromServer(data.chat_history);
    } else if (data.reply) {
      // fallback: add bot reply using ISO timestamp (will be reconciled next fetch)
      addChatMessage('bot', data.reply, new Date().toISOString());
    }

    // update left panel topic if server returned it
    if (data.topic) {
      updateChatListTitle(chatSessionId, data.topic);
      const chatTitleEl = document.getElementById('chatTitle');
      if (chatTitleEl) chatTitleEl.textContent = data.topic;
    }
  })
  .catch(err => {
    console.error('Chat send error', err);
    // optionally show flash
  });
});

// ----- keep the rest of your utilities and UI logic unchanged (only minor edits to use chatSessionId) -----
function updateChatListTitle(sessionId, newTitle) {
  if (!sessionId || !newTitle) return;
  const anchor = document.querySelector(`.chat-history-btn[data-session-id="${sessionId}"]`);
  if (!anchor) return;

  const dateSpan = anchor.querySelector('.chat-history-date');
  if (dateSpan) {
    anchor.textContent = newTitle + ' ';
    anchor.appendChild(dateSpan);
  } else {
    anchor.textContent = newTitle;
  }
}


/* INLINE RENAME: exposed as window.startInlineRename(sessionItemOrSessionId) */
window.startInlineRename = function(sessionItemOrId) {
  // accept either the .chat-history-item element or a session id string
  let item = (typeof sessionItemOrId === 'string')
    ? document.querySelector(`.chat-history-item[data-session-id="${sessionItemOrId}"]`)
    : sessionItemOrId;

  if (!item) {
    console.warn('startInlineRename: chat-history-item not found for', sessionItemOrId);
    return;
  }

  const anchor = item.querySelector('.chat-history-btn');
  if (!anchor) return;
  const topicSpan = anchor.querySelector('.chat-topic');
  const dateSpan = anchor.querySelector('.chat-history-date');
  const current = topicSpan ? topicSpan.textContent.trim() : '';

  // build simple inline editor
  const input = document.createElement('input');
  input.type = 'text'; input.className = 'rename-input'; input.value = current;
  input.maxLength = 160; input.style.width = '70%';

  const saveBtn = document.createElement('button');
  saveBtn.type = 'button'; saveBtn.className = 'rename-save'; saveBtn.textContent = 'Save';

  const cancelBtn = document.createElement('button');
  cancelBtn.type = 'button'; cancelBtn.className = 'rename-cancel'; cancelBtn.textContent = 'Cancel';

  const controls = document.createElement('span');
  controls.className = 'rename-controls';
  controls.appendChild(saveBtn); controls.appendChild(cancelBtn);

  if (topicSpan) {
    topicSpan.style.display = 'none';
    topicSpan.insertAdjacentElement('afterend', input);
    input.insertAdjacentElement('afterend', controls);
  } else {
    anchor.insertBefore(input, dateSpan);
    anchor.insertBefore(controls, dateSpan);
  }

  input.focus();
  try { input.setSelectionRange(0, input.value.length); } catch(e){}

  const cleanup = () => {
    input.remove(); controls.remove(); if (topicSpan) topicSpan.style.display = '';
  };

  const doSave = () => {
    const newTitle = input.value.trim();
    if (!newTitle) { cleanup(); return; }
    const sessionId = item.dataset.sessionId;
    fetch('/ajax/chat/rename', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': '{{ csrf_token() }}'
      },
      body: JSON.stringify({ chat_session_id: sessionId, title: newTitle })
    })
    .then(r => r.json())
    .then(data => {
      if (data && data.success) {
        // update the topic in-place and left-panel entry
        if (topicSpan) topicSpan.textContent = data.title;
        const leftAnchor = document.querySelector(`.chat-history-btn[data-session-id="${sessionId}"]`);
        if (leftAnchor) {
          const leftDate = leftAnchor.querySelector('.chat-history-date');
          let leftTopic = leftAnchor.querySelector('.chat-topic');
          if (leftTopic) leftTopic.textContent = data.title;
          else {
            leftAnchor.textContent = data.title + (leftDate ? ' ' : '');
            if (leftDate) leftAnchor.appendChild(leftDate);
          }
        }
      } else {
        alert('Rename failed: ' + (data && data.error ? data.error : 'Unknown error'));
      }
    })
    .catch(err => {
      console.error('rename request failed', err);
      alert('Rename request failed. See console.');
    })
    .finally(() => cleanup());
  };

  cancelBtn.addEventListener('click', (e) => { e.preventDefault(); cleanup(); });
  saveBtn.addEventListener('click', (e) => { e.preventDefault(); doSave(); });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); doSave(); }
    if (e.key === 'Escape') { e.preventDefault(); cleanup(); }
  });

  // if user blurs, close after small delay unless Save/Cancel focused
  input.addEventListener('blur', () => {
    setTimeout(() => {
      if (document.activeElement === saveBtn || document.activeElement === cancelBtn) return;
      cleanup();
    }, 150);
  });
};


/* fixed three-dot menu: body portal + keep sessionId so rename/delete still work */
(function(){
  let openPanel = null, openBtn = null, original = null;

  function pos(btn, panel){
    const r = btn.getBoundingClientRect();
    const p = panel.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    const vh = document.documentElement.clientHeight;

    // compute left (prefer right side of button)
    let left = r.right - p.width;
    if (left + p.width > vw - 8) left = r.left - p.width - 6;
    if (left < 8) left = Math.max(8, r.left);

    // compute top (prefer below button)
    let top = r.bottom + 6;
    if (top + p.height > vh - 8) top = Math.max(8, r.top - p.height - 6);

    panel.style.left = Math.round(left) + 'px';
    panel.style.top = Math.round(top) + 'px';
  }

  function open(btn){
    const sessionMenu = btn.closest('.session-menu');
    if (!sessionMenu) return;
    const panel = sessionMenu.querySelector('.menu-panel');
    if (!panel) return;
    if (openPanel && openPanel !== panel) close();

    // if we move panel out to body, remember original parent & next sibling
    if (panel.parentNode !== document.body) {
      original = { parent: panel.parentNode, next: panel.nextSibling };
      // store originating chat id on panel so handlers still know which chat it belongs to
      const owner = sessionMenu.closest('.chat-history-item');
      if (owner && owner.dataset && owner.dataset.sessionId) panel.dataset.sessionId = owner.dataset.sessionId;
      document.body.appendChild(panel);
    }

    // ensure fixed positioning + reset conflicting CSS that may cause full width
    panel.style.position = 'fixed';
    panel.style.zIndex = 99999;
    panel.style.display = 'block';
    panel.style.right = 'auto';       // override CSS right:0 if present
    panel.style.width = 'auto';       // prevent full-width
    panel.style.minWidth = panel.style.minWidth || '120px';
    panel.classList.add('show');
    btn.setAttribute('aria-expanded','true');

    openPanel = panel;
    openBtn = btn;

    requestAnimationFrame(()=>pos(btn, panel));
  }

  function close(){
    if (!openPanel) return;
    if (openBtn) openBtn.setAttribute('aria-expanded','false');

    openPanel.classList.remove('show');
    openPanel.style.display = 'none';
    openPanel.style.left = '';
    openPanel.style.top = '';
    openPanel.style.position = '';
    openPanel.style.zIndex = '';
    openPanel.style.right = '';
    openPanel.style.width = '';

    // restore to original DOM location
    if (original && original.parent) {
      try { original.parent.insertBefore(openPanel, original.next); }
      catch(e){ original.parent.appendChild(openPanel); }
      original = null;
    }

    // don't wipe dataset.sessionId here — keeping it is harmless but you can remove if desired
    openPanel = openBtn = null;
  }

  // delegated clicks
  document.addEventListener('click', function(e){
    const btn = e.target.closest('.menu-btn');
    if (btn) {
      e.preventDefault(); e.stopPropagation();
      const panel = btn.closest('.session-menu')?.querySelector('.menu-panel');
      if (!panel) return;
      panel.classList.contains('show') ? close() : open(btn);
      return;
    }

    // rename clicked inside menu (panel may be moved to body) — find sessionId on panel or ancestor
    const renameBtn = e.target.closest('.rename-item');
    if (renameBtn) {
      e.stopPropagation();
      const panel = renameBtn.closest('.menu-panel');
      // prefer panel.dataset.sessionId (set when we opened the menu), fallback to closest .chat-history-item
      const sessionId = (panel && panel.dataset && panel.dataset.sessionId) ||
                        renameBtn.closest('.chat-history-item')?.dataset?.sessionId;
      if (sessionId) {
        // find the chat-history-item element to pass to startInlineRename if it expects DOM node
        const item = document.querySelector(`.chat-history-item[data-session-id="${sessionId}"]`);
        if (typeof window.startInlineRename === 'function') {
          if (item) window.startInlineRename(item);
          else console.warn('startInlineRename: cannot find chat-history-item for', sessionId);
        } else {
          console.warn('startInlineRename not defined');
        }
      } else {
        console.warn('rename: session id not found');
      }
      close();
      return;
    }

    // delete clicked inside menu
    const deleteBtn = e.target.closest('.delete-item');
    if (deleteBtn) {
      e.stopPropagation();
      const panel = deleteBtn.closest('.menu-panel');
      const sessionId = (panel && panel.dataset && panel.dataset.sessionId) ||
                        deleteBtn.closest('.chat-history-item')?.dataset?.sessionId;
      if (sessionId && typeof window.confirmDelete === 'function') {
        window.confirmDelete(sessionId, new Event('click'));
      } else {
        console.warn('confirmDelete not available or sessionId missing', sessionId);
      }
      close();
      return;
    }

    // click outside menu -> close
    if (openPanel && !e.target.closest('.menu-panel') && !e.target.closest('.menu-btn')) close();
  }, false);

  // reposition on resize/scroll
  window.addEventListener('resize', ()=>{ if (openPanel) requestAnimationFrame(()=>pos(openBtn, openPanel)); }, true);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
})();

// theme toggles unchanged
const lightToggle = document.getElementById("lightModeToggle");
const darkToggle = document.getElementById("darkModeToggle");
if (localStorage.getItem("theme") === "light") {
  document.body.classList.add("light-mode");
}
if (lightToggle) lightToggle.addEventListener("click", () => {
  document.body.classList.add("light-mode");
  localStorage.setItem("theme", "light");
});
if (darkToggle) darkToggle.addEventListener("click", () => {
  document.body.classList.remove("light-mode");
  localStorage.setItem("theme", "dark");
});

// delete chat buttons (unchanged logic)
document.querySelectorAll('.delete-chat-btn').forEach(button => {
  button.addEventListener('click', () => {
    const sessionId = button.getAttribute('data-session-id');
    fetch(`/delete-chat/${sessionId}`, { method: 'DELETE' })
    .then(response => {
      if (response.ok) {
        location.reload();
      } else {
        console.error("Failed to delete chat");
      }
    })
    .catch(error => {
      console.error("Error deleting chat:", error);
    });
  });
});

// textarea autosize unchanged
const textarea = document.getElementById('chatInput');
if (textarea) {
  textarea.addEventListener('input', function () {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 150) + 'px';
  });
}

// Speech recognition logic (unchanged) - kept as-is
let recognition;
let isListening = false;
let finalTranscript = '';
const micButton = document.getElementById('micButton');
const chatInput = document.getElementById('chatInput');
if ('webkitSpeechRecognition' in window) {
  recognition = new webkitSpeechRecognition();
  recognition.continuous = true;
  recognition.interimResults = true;
  recognition.lang = 'en-US';
  recognition.onresult = function(event) {
    let interimTranscript = '';
    let newFinalTranscript = finalTranscript;
    for (let i = event.resultIndex; i < event.results.length; ++i) {
      if (event.results[i].isFinal) {
        newFinalTranscript += event.results[i][0].transcript + ' ';
      } else {
        interimTranscript += event.results[i][0].transcript;
      }
    }
    finalTranscript = newFinalTranscript;
    chatInput.value = finalTranscript + interimTranscript;
    chatInput.style.height = 'auto';
    chatInput.style.height = (chatInput.scrollHeight) + 'px';
  };
  recognition.onerror = function(event) {
    isListening = false;
    micButton.classList.remove('listening');
    chatInput.placeholder = 'Click mic to start speaking...';
  };
  recognition.onspeechend = function() {
    recognition.stop();
    isListening = false;
    micButton.classList.remove('listening');
    chatInput.placeholder = 'Click mic to start speaking...';
  };
  function startListening() {
    if (!isListening) {
      recognition.start();
      isListening = true;
      micButton.classList.add('listening');
      chatInput.placeholder = 'Listening...';
    }
  }
  function stopListening() {
    if (isListening) {
      recognition.stop();
      isListening = false;
      micButton.classList.remove('listening');
      chatInput.placeholder = 'Click mic to start speaking...';
    }
  }
  if (micButton) micButton.addEventListener('click', function() {
    if (isListening) {
      stopListening();
    } else {
      startListening();
    }
  });
  if (chatInput) chatInput.addEventListener('input', function() {
    if (chatInput.value === '') {
      finalTranscript = '';
    }
    chatInput.style.height = 'auto';
    chatInput.style.height = (chatInput.scrollHeight) + 'px';
  });
} else if (!('webkitSpeechRecognition' in window)) {
  
}

// copy/speak/delete-message delegation (keeps behavior but slightly simplified)
document.addEventListener('click', function(e) {
  const copyBtn = e.target.closest('.copy-button');
  if (copyBtn) {
    const messageDiv = copyBtn.closest('.chat-message');
    const botResponse = messageDiv && messageDiv.querySelector('.bot-response');
    if (botResponse) {
      navigator.clipboard.writeText(botResponse.textContent.trim()).then(() => {
        copyBtn.innerHTML = '<i class="fas fa-check"></i>';
        setTimeout(() => copyBtn.innerHTML = '<i class="fas fa-copy"></i>', 1200);
      });
    }
    return;
  }

  const speakBtn = e.target.closest('.speak-button');
  if (speakBtn) {
    const messageDiv = speakBtn.closest('.chat-message');
    const botResponse = messageDiv && messageDiv.querySelector('.bot-response');
    if (!botResponse) return;
    if (!('speechSynthesis' in window)) { alert('Sorry, your browser does not support text-to-speech.'); return; }
    if (window.speechSynthesis.speaking) { window.speechSynthesis.cancel(); return; }
    const text = botResponse.textContent.trim();
    if (!text) return;
    const utterance = new SpeechSynthesisUtterance(text);
    window.speechSynthesis.speak(utterance);
    return;
  }

  const delBtn = e.target.closest('.delete-message-btn');
  if (delBtn) {
    if (!confirm('Are you sure you want to delete this message?')) return;
    const messageIndex = delBtn.dataset.messageIndex || -1;
    const sessionId = delBtn.dataset.sessionId;
    fetch(`/delete-message/${sessionId}/${messageIndex}`, { method: 'DELETE' })
      .then(response => {
        if (response.ok) location.reload(); else alert('Failed to delete message');
      });
    return;
  }
});

// delete-chat confirm (unchanged logic but adapted)
function confirmDelete(chatId, event) {
  event.stopPropagation();
  if (confirm("Permanently delete this chat?")) {
    fetch(`/delete-chat/${chatId}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': '{{ csrf_token() }}' }
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        window.location.reload();
      } else {
        alert('Delete failed: ' + (data.error || 'Unknown error'));
      }
    })
    .catch(error => console.error('Error:', error));
  }
}

// initial UI tweaks (focus and enter-to-send) - unchanged behavior
document.addEventListener('DOMContentLoaded', function() {
  const chatInput = document.getElementById('chatInput');
  const chatForm = document.getElementById('chatForm');
  const sendButton = document.getElementById('sendButton');
  if (chatInput) chatInput.focus();
  if (chatInput) chatInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (sendButton) sendButton.click();
    }
  });
  if (chatForm) chatForm.addEventListener('submit', function() {
    setTimeout(() => { if (chatInput) chatInput.focus(); }, 100);
  });
});



function showWaitMessage() {
  document.getElementById("wait-msg").style.display = "flex";
}

function hideWaitMessage() {
  document.getElementById("wait-msg").style.display = "none";
}

// Example usage when sending message
document.getElementById("chatForm").addEventListener("submit", function (e) {
  e.preventDefault();
  showWaitMessage();

  fetch("/send_message", { 
    method: "POST", 
    body: new FormData(this) 
  })
  .then(resp => resp.json())
  .then(data => {
    hideWaitMessage();
    // add bot reply to chat window...
  })
  .catch(err => {
    hideWaitMessage();
    console.error(err);
  });
});
