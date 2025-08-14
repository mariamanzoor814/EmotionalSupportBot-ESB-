const lightToggle = document.getElementById("lightModeToggle");
    const darkToggle = document.getElementById("darkModeToggle");

    if (localStorage.getItem("theme") === "light") {
      document.body.classList.add("light-mode");
    }

    lightToggle.addEventListener("click", () => {
      document.body.classList.add("light-mode");
      localStorage.setItem("theme", "light");
    });

    darkToggle.addEventListener("click", () => {
      document.body.classList.remove("light-mode");
      localStorage.setItem("theme", "dark");
    });

    document.querySelectorAll('.delete-chat-btn').forEach(button => {
      button.addEventListener('click', () => {
        const sessionId = button.getAttribute('data-session-id');
        fetch(`/delete-chat/${sessionId}`, {
          method: 'DELETE',
        })
        .then(response => {
          if (response.ok) {
            location.reload(); // Reload the page to update the history
          } else {
            console.error("Failed to delete chat");
          }
        })
        .catch(error => {
          console.error("Error deleting chat:", error);
        });
      });
    });

      const textarea = document.getElementById('chatInput');
      
      textarea.addEventListener('input', function () {
        this.style.height = 'auto'; 
        this.style.height = Math.min(this.scrollHeight, 150) + 'px'; // Don't exceed 150px
      });

   // Global variables
  let recognition;
  let isListening = false;
  let finalTranscript = ''; // Holds the final, complete transcript

  const micButton = document.getElementById('micButton');
  const chatInput = document.getElementById('chatInput');

  // Check for browser support
  if ('webkitSpeechRecognition' in window) {
    recognition = new webkitSpeechRecognition();
    recognition.continuous = true; // Allow continuous speech recognition
    recognition.interimResults = true; // Allow interim results
    recognition.lang = 'en-US'; // Set language to US English

    // When results are received
    recognition.onresult = function(event) {
      let interimTranscript = '';
      let newFinalTranscript = finalTranscript;

      for (let i = event.resultIndex; i < event.results.length; ++i) {
        if (event.results[i].isFinal) {
          newFinalTranscript += event.results[i][0].transcript + ' '; // Add final transcript
        } else {
          interimTranscript += event.results[i][0].transcript; // Show interim transcript
        }
      }

      finalTranscript = newFinalTranscript; // Update the final transcript
      chatInput.value = finalTranscript + interimTranscript; // Update chat input with both final & interim text

      // Resize input to fit content
      chatInput.style.height = 'auto'; // Reset height
      chatInput.style.height = (chatInput.scrollHeight) + 'px'; // Set new height
    };

    // Handle speech recognition errors
    recognition.onerror = function(event) {
      console.error('Speech recognition error:', event.error);
      isListening = false;
      micButton.classList.remove('listening');
      chatInput.placeholder = 'Click mic to start speaking...'; // Reset placeholder
    };

    // When speech recognition ends (user pauses or stops speaking)
    recognition.onspeechend = function() {
      console.log('Speech recognition ended (pause detected).');
      recognition.stop();
      isListening = false;
      micButton.classList.remove('listening'); // Stop glowing when speech stops
      chatInput.placeholder = 'Click mic to start speaking...'; // Reset placeholder
    };
  } else {
    alert('Speech Recognition not supported in this browser!');
  }

  // Start recognition when the mic button is pressed
  function startListening() {
    if (!isListening) {
      recognition.start();
      isListening = true;
      micButton.classList.add('listening'); // Add glow when speaking starts
      chatInput.placeholder = 'Listening...'; // Change placeholder to "Listening..."
      console.log('🎙️ Listening started...');
    }
  }

  // Stop recognition when the mic button is released
  function stopListening() {
    if (isListening) {
      recognition.stop();
      isListening = false;
      micButton.classList.remove('listening'); // Stop glowing
      chatInput.placeholder = 'Click mic to start speaking...'; // Reset placeholder
      console.log('🛑 Listening stopped.');
    }
  }

  // Event listener for clicking mic button to start/stop recognition
  micButton.addEventListener('click', function() {
    if (isListening) {
      stopListening(); // If already listening, stop
    } else {
      startListening(); // Otherwise, start listening
    }
  });

  // Clear the finalTranscript when the user manually deletes the text
  chatInput.addEventListener('input', function() {
    if (chatInput.value === '') {
      finalTranscript = ''; // Clear transcript when input is cleared
    }

    // Resize input to fit content on typing
    chatInput.style.height = 'auto'; // Reset height
    chatInput.style.height = (chatInput.scrollHeight) + 'px'; // Set new height
  });
  
  function speakTextFromButton(button) {
    if (!('speechSynthesis' in window)) {
      console.error('Text-to-speech not supported.');
      return;
    }
  
    const isSpeaking = window.speechSynthesis.speaking;
  
    if (isSpeaking) {
      // If already speaking, stop it
      window.speechSynthesis.cancel();
      button.textContent = 'Speak';  // Reset button text
    } else {
      const messageBubble = button.closest('.message-bubble');
      const botResponse = messageBubble.querySelector('.bot-response');
  
      if (botResponse) {
        const text = botResponse.textContent.trim();
        if (text) {
          const utterance = new SpeechSynthesisUtterance(text);
          utterance.lang = 'en-US';
          utterance.rate = 1;
          utterance.pitch = 1;
          utterance.volume = 1;
  
          utterance.onend = function() {
            // When speech ends, reset the button text
            button.textContent = 'Speak';
          };
  
          window.speechSynthesis.speak(utterance);
          button.textContent = 'Stop';  // Change button text to Stop
        } else {
          console.error('No text to speak!');
        }
      } else {
        console.error('Bot response not found!');
      }
    }
  }
  
  function copyToClipboard(button) {
    const messageBubble = button.closest('.message-bubble');
    const botResponse = messageBubble.querySelector('.bot-response');
  
    if (botResponse) {
      const text = botResponse.textContent.trim();
      navigator.clipboard.writeText(text)
        .then(() => {
          button.textContent = "Copied!";
          setTimeout(() => {
            button.textContent = "Copy";
          }, 1500);
        })
        .catch(err => {
          console.error('Error copying text: ', err);
        });
    } else {
      console.error('Bot response not found!');
    }
  }