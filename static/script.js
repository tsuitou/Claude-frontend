const { createApp, ref, computed, onMounted, nextTick, watch } = Vue;

// マークダウンとコードハイライトの設定
const md = window.markdownit({
  html: false,
	breaks: true,
  linkify: true,
  typographer: true,
  highlight: function(str, lang) {
    if (lang && hljs.getLanguage(lang)) {
      try {
        return hljs.highlight(str, { language: lang }).value;
      } catch (__) {}
    }
    return ''; // 外部のデフォルトエスケープを使用
  }
});

// コードコピー機能のグローバル関数
window.copyToClipboard = function(button) {
  // data-code 属性からコードを取得
  const encodedCode = button.getAttribute('data-code');
  const decodedCode = decodeURIComponent(encodedCode);
  
  navigator.clipboard.writeText(decodedCode)
    .then(() => {
      const originalText = button.innerHTML;
      button.innerHTML = '<i class="fas fa-check"></i> コピー完了';
      setTimeout(() => {
        button.innerHTML = originalText;
      }, 2000);
    })
    .catch(err => {
      console.error('クリップボードへのコピーに失敗しました', err);
    });
};

window.openImageViewer = function(img) {
  const viewer = document.createElement('div');
  viewer.className = 'image-viewer';
  
  const imgClone = document.createElement('img');
  imgClone.src = img.src;
  imgClone.alt = img.alt || 'Generated Image';
  
  // 画像ダウンロードボタン追加
  const downloadBtn = document.createElement('button');
  downloadBtn.className = 'image-download-btn';
  downloadBtn.innerHTML = '<i class="fas fa-download"></i>';
  downloadBtn.onclick = (e) => {
    e.stopPropagation();
    
    // 画像のURLからファイル名を抽出（URLの最後の部分）
    let filename = 'generated-image.png';
    
    // 通常のURL（/static/images/...）の場合
    if (img.src.startsWith('/') || img.src.startsWith('http')) {
      const urlParts = img.src.split('/');
      if (urlParts.length > 0) {
        filename = urlParts[urlParts.length - 1];
      }
    }
    
    // データURLの場合はMIMEタイプから拡張子を決定
    if (img.src.startsWith('data:')) {
      const mimeMatch = img.src.match(/data:([a-z]+)\/([a-z0-9.]+);base64,/i);
      if (mimeMatch && mimeMatch[2]) {
        const ext = mimeMatch[2] === 'jpeg' ? 'jpg' : mimeMatch[2];
        filename = `generated-image.${ext}`;
      }
    }
    
    // ダウンロードリンクを作成
    const downloadLink = document.createElement('a');
    downloadLink.href = img.src;
    downloadLink.download = filename;
    downloadLink.style.display = 'none';
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);
  };
  
  // 閉じるボタン追加
  const closeBtn = document.createElement('button');
  closeBtn.className = 'image-close-btn';
  closeBtn.innerHTML = '<i class="fas fa-times"></i>';
  closeBtn.onclick = (e) => {
    e.stopPropagation();
    document.body.removeChild(viewer);
  };
  
  // 要素を追加
  viewer.appendChild(imgClone);
  viewer.appendChild(downloadBtn);
  viewer.appendChild(closeBtn);
  
  // 背景クリックでも閉じる
  viewer.onclick = (e) => {
    if (e.target === viewer) {
      document.body.removeChild(viewer);
    }
  };
  
  document.body.appendChild(viewer);
};


// ファイルのMIMEタイプとファイル拡張子のマッピング
const EXTENSION_TO_MIME = {
  pdf: "application/pdf", js: "application/x-javascript",
  py: "text/x-python", css: "text/css", md: "text/md",
  csv: "text/csv", xml: "text/xml", rtf: "text/rtf",
  txt: "text/plain", png: "image/png", jpeg: "image/jpeg",
  jpg: "image/jpeg", webp: "image/webp", heic: "image/heic",
  heif: "image/heif", mp4: "video/mp4", mpeg: "video/mpeg",
  mov: "video/mov", avi: "video/avi", flv: "video/x-flv",
  mpg: "video/mpg", webm: "video/webm", wmv: "video/wmv",
  "3gpp": "video/3gpp", wav: "audio/wav", mp3: "audio/mp3",
  aiff: "audio/aiff", aac: "audio/aac", ogg: "audio/ogg",
  flac: "audio/flac"
};

// Vueアプリケーション
createApp({
  setup() {
    // =====================================
    // 状態変数
    // =====================================
    
    // 認証関連
    const isLoggedIn = ref(false);
    const authMode = ref('login');
    const username = ref('');
    const password = ref('');
    const authError = ref('');
    const token = ref('');
    
    // チャット関連
    const currentChatId = ref(null);
    const chatHistory = ref({});
    const currentChat = ref(null);
    const selectedModel = ref('');
    const models = ref([]);
    const messageText = ref('');
    const isGenerating = ref(false);
		const streamEnabled = ref(true);
    
    // UI状態
    const searchQuery = ref('');
    const showEditTitleModal = ref(false);
    const editTitleText = ref('');
    const showDeleteConfirmModal = ref(false);
    const deleteChatId = ref(null);
    const showToast = ref(false);
    const toastMessage = ref('');
    const editingMessageId = ref(null);  // 編集中のメッセージID
    const editingMessageText = ref('');  // 編集中のメッセージテキスト
		const isSidebarOpen = ref(false);
		const isMobile = ref(window.innerWidth <= 480);
		
    // ファイル添付
    const attachments = ref([]);
    const isDraggingOver = ref(false)
		
    // DOM参照
    const messagesContainer = ref(null);
    const messageInput = ref(null);
    const fileInput = ref(null);
    
    // Socket.IO接続
    const socket = io();
    
    // =====================================
    // 計算プロパティ
    // =====================================
    
		// フィルタリングされた履歴リスト（IDの降順）
		const filteredHistory = computed(() => {
			const history = Object.entries(chatHistory.value)
				.map(([id, chat]) => ({ id, ...chat }))
				.sort((a, b) => b.id.localeCompare(a.id)); // IDの降順（新しいIDが大きい場合）
			
			if (!searchQuery.value) return history;
			
			const query = searchQuery.value.toLowerCase();
			return history.filter(chat => 
				chat.title.toLowerCase().includes(query)
			);
		});

		// ブックマークされたチャットのリスト（同様にIDでソート）
		const bookmarkedChats = computed(() => {
			return Object.entries(chatHistory.value)
				.filter(([_, chat]) => chat.bookmarked)
				.map(([id, chat]) => ({ id, ...chat }))
				.sort((a, b) => b.id.localeCompare(a.id)); // IDの降順
		});
    
    // 現在のチャットがブックマークされているか
    const isCurrentChatBookmarked = computed(() => {
      if (!currentChatId.value || !chatHistory.value[currentChatId.value]) return false;
      return chatHistory.value[currentChatId.value].bookmarked;
    });
    
    // メッセージを送信できるか
    const canSendMessage = computed(() => {
      return (messageText.value.trim() !== '' ) && !isGenerating.value;
    });
    
    // =====================================
    // メソッド
    // =====================================
    
    // ---------- 認証関連 ----------
    
    // 認証フォーム送信
    const submitAuth = () => {
      if (!username.value || !password.value) {
        authError.value = 'ユーザー名とパスワードを入力してください';
        return;
      }
      
      if (authMode.value === 'login') {
        login();
      } else {
        register();
      }
    };
    
    // ユーザー登録
    const register = () => {
      socket.emit('register', {
        username: username.value,
        password: password.value
      });
    };
    
    // ログイン
    const login = () => {
      socket.emit('login', {
        username: username.value,
        password: password.value
      });
    };
    
    // 自動ログイン
    const autoLogin = () => {
      const savedToken = localStorage.getItem('claude_auth_token');
      if (savedToken) {
        token.value = savedToken;
        socket.emit('auto_login', { token: savedToken });
      }
    };
    
    // ログアウト
    const logout = () => {
      localStorage.removeItem('claude_auth_token');
      token.value = '';
      isLoggedIn.value = false;
      currentChat.value = null;
      currentChatId.value = null;
      chatHistory.value = {};
    };
   // ---------- モバイル ----------
		// モバイルサイドバー切り替え関数
		const toggleSidebar = () => {
			isSidebarOpen.value = !isSidebarOpen.value;
			
			// サイドバーが開いたときにスクロールを無効化
			if (isSidebarOpen.value) {
				document.body.style.overflow = 'hidden';
			} else {
				document.body.style.overflow = '';
			}
		};

		// サイドバーを閉じる関数
		const closeSidebar = () => {
			isSidebarOpen.value = false;
			document.body.style.overflow = '';
		};

		// モバイルでのチャット読み込み時にサイドバーを閉じる
		const loadChatMobile = (chatId) => {
			loadChat(chatId);
			if (isMobile.value) {
				closeSidebar();
			}
		};

		// ウィンドウサイズ変更検知
		const handleResize = () => {
			isMobile.value = window.innerWidth <= 480;
			if (!isMobile.value) {
				// モバイルではない場合、サイドバーを閉じる必要はない
				document.body.style.overflow = '';
			}
		};
    // ---------- チャット管理 ----------
    
    // 新規チャットの作成
    const createNewChat = () => {
			isGenerating.value = false;
			cancelEditMessage();
      socket.emit('new_chat', { token: token.value });
    };
    
    // チャットの読み込み
    const loadChat = (chatId) => {
			cancelEditMessage();
      currentChatId.value = chatId;
      socket.emit('load_chat', { token: token.value, chat_id: chatId });
    };
    
    // チャットの削除前確認
    const confirmDeleteChat = (chatId) => {
      deleteChatId.value = chatId;
      showDeleteConfirmModal.value = true;
    };
    
    // チャットの削除
    const deleteChat = () => {
      socket.emit('delete_chat', { token: token.value, chat_id: deleteChatId.value });
      showDeleteConfirmModal.value = false;
      
      // 現在表示中のチャットが削除対象の場合
      if (currentChatId.value === deleteChatId.value) {
        currentChatId.value = null;
        currentChat.value = null;
      }
    };
    
    // ブックマークの切り替え
    const toggleBookmark = (chatId) => {
      socket.emit('toggle_bookmark', { token: token.value, chat_id: chatId });
    };
    
    // チャットタイトル編集モーダルを開く
    const openEditTitleModal = () => {
      if (!currentChat.value) return;
      editTitleText.value = currentChat.value.title;
      showEditTitleModal.value = true;
    };
    
    // 編集したタイトルを保存
    const saveEditedTitle = () => {
      if (!editTitleText.value.trim()) {
        showToastMessage('タイトルを入力してください');
        return;
      }
      
      socket.emit('rename_chat', {
        token: token.value,
        chat_id: currentChatId.value,
        new_title: editTitleText.value.trim()
      });
      
      showEditTitleModal.value = false;
    };
    
    // 履歴リストの取得
    const getHistoryList = () => {
      socket.emit('get_history_list', { token: token.value });
    };
    
    // モデルリストの取得
    const getModelList = () => {
      socket.emit('get_model_list');
    };
    
    // ---------- メッセージ関連 ----------
    
		const copyMessageContent = (message) => {
			navigator.clipboard.writeText(message)
				.then(() => {
					showToastMessage('メッセージをコピーしました');
				})
				.catch(err => {
					showToastMessage('メッセージのコピーに失敗しました');
				});
		}

    // メッセージの送信
		const sendMessage = async () => {
			if (!canSendMessage.value) return;
			// 新規チャットの場合
			if (!currentChatId.value) {
				await createNewChat();
				// 新しいチャットIDが設定されるのを待つ
				await new Promise(resolve => {
					const checkInterval = setInterval(() => {
						if (currentChatId.value) {
							clearInterval(checkInterval);
							resolve();
						}
					}, 100);
				});
			}
			isGenerating.value = true;
			// 送信データの準備
			const messageData = {
				token: token.value,
				chat_id: currentChatId.value,
				message: messageText.value,
				model_name: selectedModel.value,
				stream_enabled: streamEnabled.value,
				files: [] // 複数ファイル情報を格納する配列
			};
			
			// 一時的にUIに表示するためのメッセージオブジェクト
			const userMessage = {
				role: 'user',
				content: messageText.value,
				timestamp: Date.now() / 1000,
				attachments: [] // 複数の添付ファイル情報
			};
			
			// 添付ファイルがある場合の処理
			if (attachments.value.length > 0) {
				const filesUpload = [];
				let isLargeFile = false;
				
				// すべてのファイルを処理
				for (let i = 0; i < attachments.value.length; i++) {
					const file = attachments.value[i];
					
					// ファイルサイズが大きい場合（10MB以上）かつメディアファイル
					if (file.size >= FILE_SIZE_THRESHOLD && MEDIA_EXTENSIONS.test(file.name)) {
						 isLargeFile = true;
						// 大きなファイルは非同期アップロードリクエストを準備
						const formData = new FormData();
						formData.append('file', file.file);
						formData.append('token', token.value);
						
						// アップロードリクエストをPromiseとして配列に追加
						filesUpload.push(
							fetch('/upload_large_file', {
								method: 'POST',
								body: formData
							}).then(response => response.json())
						);
					} else {
						// 通常サイズのファイル、またはExcel変換済みファイルの処理
						const filePromise = new Promise((resolve, reject) => {
							const reader = new FileReader();
							
							reader.onload = () => {
								const base64data = reader.result.split(',')[1];
								
								// messageDataのfiles配列に追加
								messageData.files.push({
									file_data: base64data,
									file_name: file.name,
									file_mime_type: file.type,
									original_file_name: file.originalName || null
								});
								
								// UIメッセージの添付ファイル情報も追加
								userMessage.attachments.push({
									name: file.name,
									type: file.type
								});
								
								resolve();
							};
							reader.onerror = reject;
							reader.readAsDataURL(file.file);
						});
						
						filesUpload.push(filePromise);
					}
				}
				
				// すべてのファイルアップロード処理を待つ
				if (filesUpload.length > 0) {
					if (isLargeFile) showToastMessage('ファイルをアップロード中...');
					
					try {
						const results = await Promise.all(filesUpload);
						
						// ファイルアップロード結果の処理
						for (const result of results) {
							// JSON応答のみを処理（base64データの場合はすでに処理済み）
							if (result && result.status === 'success') {
								// messageDataのfiles配列に追加
								messageData.files.push({
									file_id: result.file_id,
									file_name: result.file_name,
									file_mime_type: result.file_mime_type
								});
								
								// UIメッセージの添付ファイル情報も追加
								userMessage.attachments.push({
									name: result.file_name,
									type: result.file_mime_type,
									file_id: result.file_id
								});
							} else if (result && result.status === 'error') {
								isGenerating.value = false;
								showToastMessage('ファイルアップロードエラー: ' + result.message);
							}
						}
					} catch (error) {
						isGenerating.value = false;
						showToastMessage('ファイルアップロードエラー: ' + error.message);
						return;
					}
				}
			}
			
			// UIの更新
			if (!currentChat.value.messages) {
				currentChat.value.messages = [];
			}
			// UIにユーザーメッセージを追加
			currentChat.value.messages.push(userMessage);
			
			// 入力欄と添付ファイルをクリア
			messageText.value = '';
			attachments.value = [];
			// スクロールして最新メッセージを表示
			nextTick(() => {
				resizeTextarea();
				scrollToBottom();
			});
			
			// 送信とレスポンス受信開始
			socket.emit('send_message', messageData);
		};
    
    // メッセージの編集モードを開始
		const startEditMessage = (index, message) => {
			// ユーザーメッセージ「または」モデルメッセージの編集を許可
			if ((message.role !== 'user' && message.role !== 'assistant') || isGenerating.value) return;
			
			// 編集中のメッセージを設定
			editingMessageId.value = index;
			editingMessageText.value = message.content;
			
			// 次のティックでテキストエリアにフォーカスとサイズ調整
			nextTick(() => {
				const textarea = document.getElementById(`edit-message-${index}`);
				if (textarea) {
					// まずテキストエリアのサイズを調整
					textarea.style.height = 'auto';
					textarea.style.height = Math.min(textarea.scrollHeight, 300) + 'px';
					
					// その後フォーカスを設定
					textarea.focus();
					textarea.setSelectionRange(textarea.value.length, textarea.value.length);
				}
			});
		};

		// 2. saveEditMessage関数を変更：メッセージタイプによって適切なイベントを送信
		const saveEditMessage = (index) => {
			if (!editingMessageText.value.trim()) {
				showToastMessage('メッセージを入力してください');
				return;
			}
			
			const messageRole = currentChat.value.messages[index].role;
			
			if (messageRole === 'user') {
				socket.emit('edit_message', {
					token: token.value,
					chat_id: currentChatId.value,
					message_index: index,
					new_text: editingMessageText.value
				});
				
				// エディタを閉じる
				editingMessageId.value = null;
				editingMessageText.value = '';
				
				resendMessage(index);
				
			} else if (messageRole === 'assistant') {
				socket.emit('edit_model_message', {
					token: token.value,
					chat_id: currentChatId.value,
					message_index: index,
					new_text: editingMessageText.value
				});
				
				// ローカルUIを先に更新（オプティミスティックUI更新）
				if (currentChat.value && currentChat.value.messages && index < currentChat.value.messages.length) {
					currentChat.value.messages[index].content = editingMessageText.value;
				}
				
				// 編集モードを終了
				editingMessageId.value = null;
				editingMessageText.value = '';
			}
		};
    
    // メッセージ編集をキャンセル
    const cancelEditMessage = () => {
      editingMessageId.value = null;
      editingMessageText.value = '';
    };
    
    // メッセージの再送信（再生成）
    const resendMessage = (index) => {
      if (isGenerating.value) return;
      
      // 対象のユーザーメッセージを特定
      const userMessage = currentChat.value.messages[index];
      if (!userMessage || userMessage.role !== 'user') return;
      
      socket.emit('resend_message', {
        token: token.value,
        chat_id: currentChatId.value,
        message_index: index,
        model_name: selectedModel.value,
				stream_enabled: streamEnabled.value,
      });
      
      // UIから以降のモデル応答を削除（ユーザーメッセージは保持）
      // index + 1以降の最初のモデルメッセージ以降を削除
      let modelIndex = -1;
      for (let i = index + 1; i < currentChat.value.messages.length; i++) {
        if (currentChat.value.messages[i].role === 'assistant') {
          modelIndex = i;
          break;
        }
      }
      
      if (modelIndex !== -1) {
        currentChat.value.messages = currentChat.value.messages.slice(0, modelIndex);
      }
      
      // モデル応答用の仮のエントリを追加
      currentChat.value.messages.push({
        role: 'assistant',
        content: '',
        timestamp: Date.now() / 1000
      });
      
      isGenerating.value = true;
    };
    
    // メッセージの削除
    const deleteMessage = (index) => {
      if (isGenerating.value) return;
      
      socket.emit('delete_message', {
        token: token.value,
        chat_id: currentChatId.value,
        message_index: index
      });
      
      // UIからメッセージを削除（指定インデックス以降をすべて削除）
      currentChat.value.messages = currentChat.value.messages.slice(0, index);
    };
    
    // 生成の中断
    const cancelGeneration = () => {
      socket.emit('cancel_stream', { 
        token: token.value,
        chat_id: currentChatId.value
      });
      
    };
    
    // ---------- UI操作 ----------
    
    // テキストエリアのリサイズ
    const resizeTextarea = () => {
      const textarea = messageInput.value;
      if (!textarea) return;
      
      textarea.style.height = 'auto';
      textarea.style.height = Math.min(textarea.scrollHeight, 300) + 'px';
    };
    
    // 編集用テキストエリアの調整
    const adjustEditTextarea = (event) => {
      const textarea = event.target;
      textarea.style.height = 'auto';
      textarea.style.height = Math.min(textarea.scrollHeight, 300) + 'px';
    };
    
    // 編集用テキストエリアのタブ処理
    const handleEditTab = (event) => {
      const textarea = event.target;
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      
      // 現在の選択範囲を保存
      const selection = textarea.value.substring(start, end);
      
      // 編集履歴を保持するために、execCommandを使用
      if (selection) {
        // 選択範囲がある場合
        const lines = selection.split('\n');
        const indentedLines = lines.map(line => '    ' + line);
        const indentedText = indentedLines.join('\n');
        
        // 新しいテキスト
        editingMessageText.value = 
          textarea.value.substring(0, start) + 
          indentedText + 
          textarea.value.substring(end);
          
        // カーソル位置を設定
        nextTick(() => {
          textarea.focus();
          textarea.setSelectionRange(start, start + indentedText.length);
        });
      } else {
        // 選択範囲がない場合
        const tab = '    ';
        editingMessageText.value = 
          textarea.value.substring(0, start) + 
          tab + 
          textarea.value.substring(end);
          
        // カーソル位置を設定
        nextTick(() => {
          textarea.focus();
          textarea.setSelectionRange(start + tab.length, start + tab.length);
        });
      }
    };
    
    // 編集用テキストエリアのShift+Tab処理
    const handleEditShiftTab = (event) => {
      const textarea = event.target;
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      
      if (start !== end) {
        // 選択範囲がある場合
        const selection = textarea.value.substring(start, end);
        const lines = selection.split('\n');
        const unindentedLines = lines.map(line => 
          line.startsWith('    ') ? line.substring(4) : 
          line.startsWith('\t') ? line.substring(1) : line
        );
        const unindentedText = unindentedLines.join('\n');
        
        // 新しいテキスト
        editingMessageText.value = 
          textarea.value.substring(0, start) + 
          unindentedText + 
          textarea.value.substring(end);
          
        // カーソル位置を設定
        nextTick(() => {
          textarea.focus();
          textarea.setSelectionRange(start, start + unindentedText.length);
        });
      } else {
        // 選択範囲がない場合
        const beforeCursor = textarea.value.substring(0, start);
        const lineStart = beforeCursor.lastIndexOf('\n') + 1;
        const line = beforeCursor.substring(lineStart);
        
        if (line.startsWith('    ')) {
          editingMessageText.value = 
            textarea.value.substring(0, lineStart) + 
            line.substring(4) + 
            textarea.value.substring(start);
            
          // カーソル位置を設定
          nextTick(() => {
            textarea.focus();
            textarea.setSelectionRange(start - 4, start - 4);
          });
        } else if (line.startsWith('\t')) {
          editingMessageText.value = 
            textarea.value.substring(0, lineStart) + 
            line.substring(1) + 
            textarea.value.substring(start);
            
          // カーソル位置を設定
          nextTick(() => {
            textarea.focus();
            textarea.setSelectionRange(start - 1, start - 1);
          });
        }
      }
    };
    
    // 最下部へのスクロール
		const scrollToBottom = () => {
			if (messagesContainer.value) {
				messagesContainer.value.scrollTo({
					top: messagesContainer.value.scrollHeight,
					behavior: 'instant' // または 'auto' でもOK
				});
			}
		};
    
    // トースト通知の表示
    const showToastMessage = (message, duration = 3000) => {
      toastMessage.value = message;
      showToast.value = true;
      
      // 自動で非表示にするタイマーを設定
      if (duration > 0) {
        setTimeout(() => {
          showToast.value = false;
        }, duration);
      }
    };
    
    // トースト通知を閉じる
    const closeToast = () => {
      showToast.value = false;
    };
    
		// マークダウンのレンダリング（コードコピーボタン付き）
		const renderMarkdown = (content) => {
			if (!content) return '';
			
			// 手順1: マークダウン内のコードブロックを一時的にエスケープし、オリジナルのコードを保存
			const codeBlocks = [];
			const originalCodeContents = []; // オリジナルのコード内容を保存
			
			let processedContent = content.replace(/```([\s\S]*?)```/g, (match, codeContent) => {
				const id = `CODE_BLOCK_${codeBlocks.length}`;
				
				// コードブロックの言語を抽出（最初の行）
				let language = 'plaintext';
				let actualCode = codeContent;
				
				// 最初の行が言語指定を含むか確認
				const firstLineBreak = codeContent.indexOf('\n');
				if (firstLineBreak > 0) {
					const possibleLang = codeContent.substring(0, firstLineBreak).trim();
					if (possibleLang && !possibleLang.includes(' ')) {
						language = possibleLang;
						actualCode = codeContent.substring(firstLineBreak + 1);
					}
				}
				
				// オリジナルのコード内容を保存（言語指定を除く）
				originalCodeContents.push({
					code: actualCode.trim(),
					language: language
				});
				
				codeBlocks.push(match);
				return id;
			});
			
			// 手順2: インラインコードもエスケープ
			const inlineCodes = [];
			processedContent = processedContent.replace(/`([^`]+)`/g, (match) => {
				const id = `INLINE_CODE_${inlineCodes.length}`;
				inlineCodes.push(match);
				return id;
			});
			
			// 手順3: 数式処理
			let tempContent = processedContent;
			
			// ブロック数式をHTMLプレースホルダーに置換
			const blockMathPlaceholders = [];
			tempContent = tempContent.replace(/\$\$(.*?)\$\$/g, (match, math) => {
				try {
					const rendered = katex.renderToString(math, { displayMode: true });
					const id = `BLOCK_MATH_${blockMathPlaceholders.length}`;
					blockMathPlaceholders.push(rendered);
					return id;
				} catch (e) {
					console.error('KaTeX block math error:', e);
					return match;
				}
			});
			
			// インライン数式をHTMLプレースホルダーに置換
			const inlineMathPlaceholders = [];
			tempContent = tempContent.replace(/\$(.*?)\$/g, (match, math) => {
				try {
					const rendered = katex.renderToString(math, { displayMode: false });
					const id = `INLINE_MATH_${inlineMathPlaceholders.length}`;
					inlineMathPlaceholders.push(rendered);
					return id;
				} catch (e) {
					console.error('KaTeX inline math error:', e);
					return match;
				}
			});
			
			// 手順4: コードブロックを元に戻す
			tempContent = tempContent.replace(/CODE_BLOCK_(\d+)/g, (_, index) => {
				return codeBlocks[parseInt(index)];
			});
			
			// 手順5: インラインコードを元に戻す
			tempContent = tempContent.replace(/INLINE_CODE_(\d+)/g, (_, index) => {
				return inlineCodes[parseInt(index)];
			});
			
			// 手順6: マークダウンをHTMLに変換
			let html = md.render(tempContent);
			
			// 手順7: 数式プレースホルダーを実際のHTMLに置換
			html = html.replace(/BLOCK_MATH_(\d+)/g, (_, index) => {
				return blockMathPlaceholders[parseInt(index)];
			});
			
			html = html.replace(/INLINE_MATH_(\d+)/g, (_, index) => {
				return inlineMathPlaceholders[parseInt(index)];
			});
			
			// 手順8: コードブロックに言語ラベルとコピーボタンを追加
			// ここでオリジナルのコードコンテンツを使用
			let codeBlockIndex = 0;
			html = html.replace(/<pre><code class="language-([^"]*)">([\s\S]*?)<\/code><\/pre>/g, (match, language, code) => {
				// オリジナルのコードを取得（保存された順番で取得）
				if (codeBlockIndex < originalCodeContents.length) {
					const originalCode = originalCodeContents[codeBlockIndex].code;
					const escapedOriginalCode = encodeURIComponent(originalCode);
					const displayLang = language === 'plaintext' ? 'Text' : language.toUpperCase();
					codeBlockIndex++;
					
					return `<pre data-language="${displayLang}"><code class="language-${language}">${code}</code><button class="code-copy-btn" data-code="${escapedOriginalCode}" onclick="copyToClipboard(this)"><i class="fas fa-copy"></i> コピー</button></pre>`;
				}
				return match; // フォールバック: 何かがおかしい場合は元のマッチを返す
			});
			
			// 手順9: 画像をクリック可能にする（lightbox風の機能）
			html = html.replace(/<img src="([^"]+)" alt="([^"]*)">/g, 
				'<img src="$1" alt="$2" class="generated-image" onclick="openImageViewer(this)">');
			
			return html;
		};
    
    // メッセージコンテンツ内のクリックイベント処理
    const handleMessageContentClick = (event) => {
      // リンクのクリック処理など
      if (event.target.tagName === 'A' && event.target.href) {
        event.preventDefault();
        window.open(event.target.href, '_blank');
      }
    };
    
    // タブキー処理（インデント）
    const handleTab = (event) => {
      const textarea = event.target;
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      
      // 選択範囲があるか
      if (start !== end) {
        // 複数行の場合
        const selectedText = textarea.value.substring(start, end);
        const lines = selectedText.split('\n');
        const indentedLines = lines.map(line => '    ' + line);
        const indentedText = indentedLines.join('\n');
        
        // テキストの置換
        const newText = textarea.value.substring(0, start) + indentedText + textarea.value.substring(end);
        
        // Vueのデータモデルを更新（テキストエリアによって異なる）
        if (textarea === messageInput.value) {
          messageText.value = newText;
        } else {
          // 編集モードのテキストエリアの場合
          editingMessageText.value = newText;
        }
        
        // カーソル位置の調整
        nextTick(() => {
          textarea.selectionStart = start;
          textarea.selectionEnd = start + indentedText.length;
        });
      } else {
        // 選択範囲がない場合
        const tab = '    ';
        const newText = textarea.value.substring(0, start) + tab + textarea.value.substring(end);
        
        // Vueのデータモデルを更新
        if (textarea === messageInput.value) {
          messageText.value = newText;
        } else {
          editingMessageText.value = newText;
        }
        
        // カーソル位置の調整
        nextTick(() => {
          textarea.selectionStart = textarea.selectionEnd = start + tab.length;
        });
      }
      
      if (textarea === messageInput.value) {
        resizeTextarea();
      }
    };
    
    // Shift+Tabキー処理（インデント解除）
    const handleShiftTab = (event) => {
      const textarea = event.target;
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      
      // 選択範囲があるか
      if (start !== end) {
        // 複数行の場合
        const selectedText = textarea.value.substring(start, end);
        const lines = selectedText.split('\n');
        const unindentedLines = lines.map(line => line.startsWith('    ') ? line.substring(4) : 
                                                  line.startsWith('\t') ? line.substring(1) : line);
        const unindentedText = unindentedLines.join('\n');
        
        // テキストの置換
        const newText = textarea.value.substring(0, start) + unindentedText + textarea.value.substring(end);
        
        // Vueのデータモデルを更新
        if (textarea === messageInput.value) {
          messageText.value = newText;
        } else {
          editingMessageText.value = newText;
        }
        
        // カーソル位置の調整
        nextTick(() => {
          textarea.selectionStart = start;
          textarea.selectionEnd = start + unindentedText.length;
        });
      } else {
        // 現在行の先頭からカーソル位置までのテキスト
        const beforeCursor = textarea.value.substring(0, start);
        const lineStart = beforeCursor.lastIndexOf('\n') + 1;
        const line = beforeCursor.substring(lineStart);
        
        // インデント解除
        let newText = textarea.value;
        let newCursorPos = start;
        
        if (line.startsWith('    ')) {
          newText = textarea.value.substring(0, lineStart) + line.substring(4) + textarea.value.substring(start);
          newCursorPos = start - 4;
        } else if (line.startsWith('\t')) {
          newText = textarea.value.substring(0, lineStart) + line.substring(1) + textarea.value.substring(start);
          newCursorPos = start - 1;
        }
        
        // Vueのデータモデルを更新
        if (textarea === messageInput.value) {
          messageText.value = newText;
        } else {
          editingMessageText.value = newText;
        }
        
        // カーソル位置の調整
        nextTick(() => {
          textarea.selectionStart = textarea.selectionEnd = newCursorPos;
        });
      }
      
      if (textarea === messageInput.value) {
        resizeTextarea();
      }
    };
    
    // タイムスタンプのフォーマット
    const formatTimestamp = (timestamp) => {
      if (!timestamp) return '';
      
      const date = new Date(timestamp * 1000);
      const now = new Date();
      const isToday = date.toDateString() === now.toDateString();
      
      if (isToday) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      } else {
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }
    };
    
		// チャットのダウンロード関数
		const downloadChat = (chatId) => {
			if (!chatId || !chatHistory.value[chatId] || !currentChat.value) return;
			
			// HTMLの生成
			const chatTitle = chatHistory.value[chatId].title;
			const messages = currentChat.value.messages;
			
			// ヘッダーとスタイルを含むHTML
			let html = `
			<!DOCTYPE html>
			<html lang="ja">
			<head>
				<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>${escapeHtml(chatTitle)}</title>
				<style>
					* {
						margin: 0;
						padding: 0;
						box-sizing: border-box;
						font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
					}
					body {
						background-color: #f9fafb;
						color: #1f2937;
						padding: 20px;
						max-width: 1000px;
						margin: 0 auto;
						line-height: 1.5;
					}
					.header {
						padding: 20px;
						margin-bottom: 20px;
					}
					.header h1 {
						font-size: 1.5rem;
					}
					.message {
						margin-bottom: 20px;
						padding: 16px;
						border-radius: 8px;
					}
					.user {
						background-color: #f0f9ff;
					}
					.model {
						background-color: #ffffff;
						box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
					}
					.message-header {
						display: flex;
						align-items: center;
						margin-bottom: 10px;
						font-weight: bold;
					}
					.user .message-header {
						color: #4f46e5;
					}
					.model .message-header {
						color: #10b981;
					}
					.timestamp {
						font-size: 0.8rem;
						color: #6b7280;
						margin-left: 10px;
					}
					.attachments {
						display: flex;
						flex-wrap: wrap;
						gap: 8px;
						margin: 8px 0;
					}
					.attachment {
						display: flex;
						align-items: center;
						gap: 6px;
						padding: 6px 10px;
						background-color: #f3f4f6;
						border: 1px solid #e5e7eb;
						border-radius: 6px;
						font-size: 13px;
					}
					/* マークダウンスタイル */
					.message-content h1,
					.message-content h2,
					.message-content h3,
					.message-content h4,
					.message-content h5,
					.message-content h6 {
						margin-top: 1.2em;
						margin-bottom: 0.6em;
						line-height: 1.25;
					}
					.message-content h1 {
						font-size: 1.8em;
						border-bottom: 1px solid #e5e7eb;
						padding-bottom: 0.3em;
					}
					.message-content h2 {
						font-size: 1.6em;
						border-bottom: 1px solid #e5e7eb;
						padding-bottom: 0.2em;
					}
					.message-content h3 { font-size: 1.4em; }
					.message-content h4 { font-size: 1.2em; }
					.message-content h5 { font-size: 1.1em; }
					.message-content h6 {
						font-size: 1em;
						color: #6b7280;
					}
					.message-content p { margin-bottom: 1em; }
					.message-content ul, 
					.message-content ol {
						margin-bottom: 1em;
						padding-left: 2em;
					}
					.message-content li { margin-bottom: 0.25em; }
					.message-content blockquote {
						padding-left: 1em;
						border-left: 4px solid #e5e7eb;
						color: #6b7280;
						margin: 1em 0;
					}
					.message-content pre {
						margin: 1em 0;
						padding: 16px;
						background-color: #1f2937;
						color: #f3f4f6;
						border-radius: 6px;
						overflow-x: auto;
						font-family: SFMono-Regular, Menlo, Monaco, Consolas, monospace;
					}
					.message-content code {
						font-family: SFMono-Regular, Menlo, Monaco, Consolas, monospace;
						font-size: 0.9em;
					}
					.message-content p code {
						background-color: #f3f4f6;
						padding: 2px 4px;
						border-radius: 4px;
						color: #1f2937;
					}
					.message-content table {
						border-collapse: collapse;
						margin: 1em 0;
						width: 100%;
					}
					.message-content th, 
					.message-content td {
						border: 1px solid #e5e7eb;
						padding: 8px 12px;
					}
					.message-content th {
						background-color: #f9fafb;
						font-weight: 600;
					}
					.message-content img {
						max-width: 100%;
						height: auto;
						border-radius: 6px;
						margin: 1em 0;
					}
					.footer {
						text-align: center;
						margin-top: 30px;
						padding: 15px;
						border-top: 1px solid #e5e7eb;
						color: #6b7280;
						font-size: 0.9rem;
					}
				</style>
			</head>
			<body>
				<div class="header">
					<h1>${escapeHtml(chatTitle)}</h1>
				</div>
			`;
			
			// メッセージごとにHTMLを生成
			messages.forEach(message => {
				const timestamp = formatTimestamp(message.timestamp);
				const role = message.role === 'user' ? 'ユーザー' : 'モデル';
				
				// コンテンツの処理
				let content = '';
				if (message.role === 'assistant') {
					// モデルのレスポンスはマークダウンをHTMLに変換
					content = md.render(message.content);
				} else {
					// ユーザーのメッセージはプレーンテキストとして処理（エスケープして改行を保持）
					content = escapeHtml(message.content).replace(/\n/g, '<br>');
				}
				
				// メッセージHTMLの生成
				html += `
				<div class="message ${message.role}">
					<div class="message-header">
						${role}
					</div>`;
				
				// 添付ファイルがある場合
				if (message.attachments && message.attachments.length > 0) {
					html += `<div class="attachments">`;
					message.attachments.forEach(attachment => {
						html += `
						<div class="attachment">
							<i class="fas ${getFileIconClass(attachment.type)}"></i>
							<span>${escapeHtml(attachment.name)}</span>
						</div>`;
					});
					html += `</div>`;
				}
				
				html += `
					<div class="message-content">
						${content}
					</div>
				</div>
				`;
			});
			
			// フッターと閉じタグの追加
			html += `
			</body>
			</html>
			`;
			
			// HTMLファイルとしてダウンロード
			const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `${chatTitle}.html`;
			document.body.appendChild(a);
			a.click();
			
			// クリーンアップ
			setTimeout(() => {
				document.body.removeChild(a);
				URL.revokeObjectURL(url);
			}, 100);
			
			showToastMessage('チャットをダウンロードしました');
		};

		// HTMLエスケープ関数
		const escapeHtml = (text) => {
			if (!text) return '';
			const map = {
				'&': '&amp;',
				'<': '&lt;',
				'>': '&gt;',
				'"': '&quot;',
				"'": '&#039;'
			};
			return text.replace(/[&<>"']/g, m => map[m]);
		};

		// ファイルアイコンのクラス名を取得（HTMLで使用）
		const getFileIconClass = (mimeType) => {
			if (!mimeType) return 'fa-file';
			
			if (mimeType.startsWith('image/')) return 'fa-image';
			if (mimeType.startsWith('text/')) return 'fa-file-alt';
			if (mimeType.startsWith('application/pdf')) return 'fa-file-pdf';
			if (mimeType.includes('spreadsheet') || mimeType.includes('csv')) return 'fa-file-excel';
			if (mimeType.includes('document') || mimeType.includes('word')) return 'fa-file-word';
			if (mimeType.includes('javascript') || mimeType.includes('python')) return 'fa-file-code';
			if (mimeType.startsWith('audio/')) return 'fa-file-audio';
			if (mimeType.startsWith('video/')) return 'fa-file-video';
			
			return 'fa-file';
		};
    // ---------- ファイル関連 ----------

		const FILE_SIZE_THRESHOLD = 10 * 1024 * 1024; // 10MB
		const ALLOWED_EXTENSIONS = /\.(pdf|js|py|css|md|csv|xml|rtf|txt|png|jpeg|jpg|webp|heic|heif|mp4|mpeg|mov|avi|flv|mpg|webm|wmv|3gpp|wav|mp3|aiff|aac|ogg|flac|xlsx|xlsm)$/i;
		const MEDIA_EXTENSIONS = /\.(mp4|mpeg|mov|avi|flv|mpg|webm|wmv|3gpp|wav|mp3|aiff|aac|ogg|flac)$/i;
		const EXCEL_EXTENSIONS = /\.(xlsx|xlsm)$/i;

    // ファイル選択ダイアログを開く
    const openFileInput = () => {
      fileInput.value.click();
    };
    
    // ファイルアップロードの処理
		const handleFileUpload = (event) => {
			const files = event.target.files;
			if (!files || files.length === 0) return;
			
			// 複数ファイルの追加処理
			for (let i = 0; i < files.length; i++) {
				const file = files[i];
				
				// 拡張子チェック
				if (!ALLOWED_EXTENSIONS.test(file.name)) {
					showToastMessage(`非対応の拡張子です: ${file.name}`);
					continue;
				}
				
				// ファイルサイズチェック
				if (file.size > FILE_SIZE_THRESHOLD) {
					// 動画・音声ファイルの場合は許可
					if (MEDIA_EXTENSIONS.test(file.name)) {
						// ファイル情報の追加
						attachments.value.push({
							name: file.name,
							type: file.type || getMimeTypeFromFilename(file.name),
							size: file.size,
							file: file
						});
					} else {
						showToastMessage(`動画・音声以外のファイルサイズ上限は10MBです: ${file.name}`);
						continue;
					}
				} else if (EXCEL_EXTENSIONS.test(file.name)) {
					// Excelファイルの変換処理
					const reader = new FileReader();
					reader.onload = (e) => {
						const data = new Uint8Array(e.target.result);
						// SheetJSでWorkbookを読み込む
						const workbook = XLSX.read(data, { type: "array" });
						// テキスト出力用の変数
						let textOutput = "";
						// 全てのシートをループしてCSV文字列に変換
						workbook.SheetNames.forEach((sheetName) => {
							const worksheet = workbook.Sheets[sheetName];
							// CSV形式で取得
							const csv = XLSX.utils.sheet_to_csv(worksheet);
							// シート名を含める
							textOutput += `=== Sheet: ${sheetName} ===\n${csv}\n\n`;
						});
						
						// 変換したテキストデータでBlobを作成
						const blob = new Blob([textOutput], { type: "text/plain" });
						const convertedFile = new File([blob], file.name.replace(/\.(xlsx|xlsm)$/i, ".txt"), {
							type: "text/plain"
						});
						
						// 変換したファイル情報を追加
						attachments.value.push({
							name: convertedFile.name,
							type: convertedFile.type,
							size: convertedFile.size,
							file: convertedFile,
							originalName: file.name
						});
					};
					reader.onerror = () => {
						showToastMessage(`Excelファイルの変換に失敗しました: ${file.name}`);
					};
					reader.readAsArrayBuffer(file);
				} else {
					// 通常のファイル処理
					attachments.value.push({
						name: file.name,
						type: file.type || getMimeTypeFromFilename(file.name),
						size: file.size,
						file: file
					});
				}
			}
			
			// 入力をリセット
			event.target.value = '';
		};
    
    // ファイル名からMIMEタイプを推測
    const getMimeTypeFromFilename = (filename) => {
      const extension = filename.split('.').pop().toLowerCase();
      return EXTENSION_TO_MIME[extension] || 'application/octet-stream';
    };
    
    // ファイルアイコンの取得
    const getFileIcon = (mimeType) => {
      if (!mimeType) return 'fa-file';
      
      if (mimeType.startsWith('image/')) return 'fa-image';
      if (mimeType.startsWith('text/')) return 'fa-file-alt';
      if (mimeType.startsWith('application/pdf')) return 'fa-file-pdf';
      if (mimeType.includes('spreadsheet') || mimeType.includes('csv')) return 'fa-file-excel';
      if (mimeType.includes('document') || mimeType.includes('word')) return 'fa-file-word';
      if (mimeType.includes('javascript') || mimeType.includes('python')) return 'fa-file-code';
      if (mimeType.startsWith('audio/')) return 'fa-file-audio';
      if (mimeType.startsWith('video/')) return 'fa-file-video';
      
      return 'fa-file';
    };
    
    // 添付ファイルの削除
    const removeAttachment = (index) => {
      attachments.value.splice(index, 1);
    };
    
		// ドラッグアンドドロップイベントハンドラー
		const handleDragOver = (event) => {
			event.preventDefault();
			isDraggingOver.value = true;
		};

		const handleDragLeave = (event) => {
			// 親要素へのバブリングを防ぐために、ドロップゾーンからの離脱のみを検出
			if (event.currentTarget === event.target || !event.currentTarget.contains(event.relatedTarget)) {
				isDraggingOver.value = false;
			}
		};

		const handleDragEnter = (event) => {
			event.preventDefault();
			isDraggingOver.value = true;
		};
		
		const handleDrop = (event) => {
			event.preventDefault();
			isDraggingOver.value = false;
			
			// ドロップされたファイルを取得
			const droppedFiles = event.dataTransfer.files;
			
			if (!droppedFiles || droppedFiles.length === 0) return;
			
			// 複数ファイルの追加処理
			for (let i = 0; i < droppedFiles.length; i++) {
				const file = droppedFiles[i];
				
				// 拡張子チェック
				if (!ALLOWED_EXTENSIONS.test(file.name)) {
					showToastMessage(`非対応の拡張子です: ${file.name}`);
					continue;
				}
				
				// ファイルサイズチェック
				if (file.size > FILE_SIZE_THRESHOLD) {
					// 動画・音声ファイルの場合は許可
					if (MEDIA_EXTENSIONS.test(file.name)) {
						// ファイル情報の追加
						attachments.value.push({
							name: file.name,
							type: file.type || getMimeTypeFromFilename(file.name),
							size: file.size,
							file: file
						});
					} else {
						showToastMessage(`動画・音声以外のファイルサイズ上限は10MBです: ${file.name}`);
						continue;
					}
				} else if (EXCEL_EXTENSIONS.test(file.name)) {
					// Excelファイルの変換処理
					const reader = new FileReader();
					reader.onload = (e) => {
						const data = new Uint8Array(e.target.result);
						// SheetJSでWorkbookを読み込む
						const workbook = XLSX.read(data, { type: "array" });
						// テキスト出力用の変数
						let textOutput = "";
						// 全てのシートをループしてCSV文字列に変換
						workbook.SheetNames.forEach((sheetName) => {
							const worksheet = workbook.Sheets[sheetName];
							// CSV形式で取得
							const csv = XLSX.utils.sheet_to_csv(worksheet);
							// シート名を含める
							textOutput += `=== Sheet: ${sheetName} ===\n${csv}\n\n`;
						});
						
						// 変換したテキストデータでBlobを作成
						const blob = new Blob([textOutput], { type: "text/plain" });
						const convertedFile = new File([blob], file.name.replace(/\.(xlsx|xlsm)$/i, ".txt"), {
							type: "text/plain"
						});
						
						// 変換したファイル情報を追加
						attachments.value.push({
							name: convertedFile.name,
							type: convertedFile.type,
							size: convertedFile.size,
							file: convertedFile,
							originalName: file.name
						});
					};
					reader.onerror = () => {
						showToastMessage(`Excelファイルの変換に失敗しました: ${file.name}`);
					};
					reader.readAsArrayBuffer(file);
				} else {
					// 通常のファイル処理
					attachments.value.push({
						name: file.name,
						type: file.type || getMimeTypeFromFilename(file.name),
						size: file.size,
						file: file
					});
				}
			}
			
			// 入力エリアにフォーカスを戻す
			messageInput.value.focus();
		};
    // =====================================
    // Socket.IO イベントハンドラ
    // =====================================
    
    // 認証関連
    socket.on('register_response', (data) => {
      if (data.status === 'success') {
        authMode.value = 'login';
        showToastMessage('登録が完了しました。ログインしてください。');
        authError.value = '';
      } else {
        authError.value = data.message || '登録に失敗しました';
      }
    });
    
    socket.on('login_response', (data) => {
      if (data.status === 'success') {
        token.value = data.auto_login_token;
        localStorage.setItem('claude_auth_token', data.auto_login_token);
        authError.value = '';
        isLoggedIn.value = true;
        
        // モデルリストとチャット履歴を取得
        getModelList();
        getHistoryList();
      } else {
        authError.value = data.message || 'ログインに失敗しました';
      }
    });
    
    socket.on('auto_login_response', (data) => {
      if (data.status === 'success') {
        token.value = data.auto_login_token;
        localStorage.setItem('claude_auth_token', data.auto_login_token);
        isLoggedIn.value = true;
        
        // モデルリストとチャット履歴を取得
        getModelList();
        getHistoryList();
      }
    });
    
    socket.on('set_username_response', (data) => {
      if (data.status === 'success') {
        isLoggedIn.value = true;
      }
    });
    
    // モデルリスト
    socket.on('model_list', (data) => {
      models.value = data.models;
      if (models.value.length > 0 && !selectedModel.value) {
        selectedModel.value = models.value[0];
      }
    });
    
    // Claude履歴
    socket.on('history_list', (data) => {
      chatHistory.value = data.history;
      
      // 現在のチャットが存在して、その情報が更新された場合
      if (currentChat.value && chatHistory.value[currentChat.value.id]) {
        currentChat.value.title = chatHistory.value[currentChat.value.id].title;
      }
    });
    
    // チャット操作
    socket.on('chat_created', (data) => {
      currentChatId.value = data.chat_id;
      // 現在のチャットを設定（履歴には追加しない）
      currentChat.value = {
        id: data.chat_id,
        title: '新しいチャット',
        messages: []
      };
    });
    
    socket.on('chat_loaded', (data) => {
      currentChat.value = {
        id: data.chat_id,
        title: chatHistory.value[data.chat_id]?.title || '読み込み中...',
        messages: data.messages
      };
      isGenerating.value = false;
      nextTick(() => {
        scrollToBottom();
      });
    });
    
    socket.on('chat_deleted', (data) => {
      if (chatHistory.value[data.chat_id]) {
        delete chatHistory.value[data.chat_id];
      }
      
      if (currentChatId.value === data.chat_id) {
        currentChatId.value = null;
        currentChat.value = null;
      }
      
      // 履歴リストを再取得
      getHistoryList();
    });
    
    socket.on('chat_renamed', (data) => {
      if (chatHistory.value[data.chat_id]) {
        chatHistory.value[data.chat_id].title = data.new_title;
      }
      
      if (currentChat.value && currentChat.value.id === data.chat_id) {
        currentChat.value.title = data.new_title;
      }
    });
    
    socket.on('bookmark_toggled', (data) => {
      if (chatHistory.value[data.chat_id]) {
        chatHistory.value[data.chat_id].bookmarked = data.bookmarked;
      }
    });
    
    // メッセージ操作
    socket.on('message_deleted', (data) => {
      if (currentChat.value && currentChat.value.messages) {
        currentChat.value.messages = currentChat.value.messages.slice(0, data.index);
        
        // 最初のメッセージが削除された場合は、チャット一覧を更新
        if (data.index === 0) {
          getHistoryList();
        }
      }
    });
    
    socket.on('message_edited', (data) => {
      if (currentChat.value && currentChat.value.messages && data.index < currentChat.value.messages.length) {
        currentChat.value.messages[data.index].content = data.new_text;
      }
    });
    
		// モデルメッセージ編集完了イベント
		socket.on('model_message_edited', (data) => {
			if (currentChat.value && currentChat.value.messages && data.index < currentChat.value.messages.length) {
				currentChat.value.messages[data.index].content = data.new_text;
			}
		});
		
    socket.on('message_resent', (data) => {
      // 再送信完了通知（必要に応じて処理）
    });
    
    // モデル応答
    socket.on('claude_response_chunk', (data) => {
      if (data.chat_id !== currentChatId.value) return;
      
      if (!isGenerating.value) {
        isGenerating.value = true;
      }
      
      // 現在のチャットの最後のメッセージを取得
      const messages = currentChat.value.messages;
      if (messages.length === 0) return;
      
      const lastMessage = messages[messages.length - 1];
      
      // 最後のメッセージがモデルのものでない場合、新しいモデルメッセージを追加
      if (lastMessage.role !== 'assistant') {
        messages.push({
          role: 'assistant',
          content: data.chunk,
          timestamp: Date.now() / 1000
        });
      } else {
        // 既存のモデルメッセージに追記
        lastMessage.content += data.chunk;
      }
      
      // 自動スクロールは行わない - ユーザーが自分でスクロールできるようにする
    });
    
    socket.on('claude_response_complete', (data) => {
      if (data.chat_id !== currentChatId.value) return;
      
      isGenerating.value = false;
      
      // チャット履歴を更新するために履歴一覧を再取得
      getHistoryList();
    });
    
    socket.on('stream_cancelled', (data) => {
      isGenerating.value = false;
      if (data.chat_id !== currentChatId.value) return;
      // チャット履歴を更新するために履歴一覧を再取得
      loadChat(data.chat_id);
    });
		
    socket.on('claude_response_error', (data) => {
      isGenerating.value = false;
      showToastMessage('エラー: ' + data.error);
      
      // エラー時に空のモデルメッセージを削除
      if (currentChat.value && currentChat.value.messages) {
        const messages = currentChat.value.messages;
        if (messages.length > 0 && messages[messages.length - 1].role === 'assistant' && !messages[messages.length - 1].content.trim()) {
          messages.pop();
        }
      }
    });
    
    // エラー処理
    socket.on('error', (data) => {
      showToastMessage('エラー: ' + data.message);
    });
    
    // =====================================
    // ライフサイクルフック
    // =====================================
    
    // コンポーネントがマウントされたときの処理
    onMounted(() => {
      // 自動ログイン試行
      autoLogin();
      
      // ソケット接続の確立
      socket.on('connect', () => {
        console.log('Socket.IO接続完了');
        if (token.value) {
          socket.emit('set_username', { token: token.value });
        }
      });
      
      socket.on('disconnect', () => {
        console.log('Socket.IO接続切断');
      });
      
      // イベントリスナーの設定
      window.addEventListener('resize', resizeTextarea);
			window.addEventListener('resize', handleResize);
      // テキストエリアの初期サイズ調整
      nextTick(() => {
        resizeTextarea();
      });
    });
    
    // ウォッチャー
    watch(messageText, () => {
      resizeTextarea();
    });
    
    // =====================================
    // 公開するプロパティとメソッド
    // =====================================
    
    return {
      // 認証関連
      isLoggedIn,
      authMode,
      username,
      password,
      authError,
      submitAuth,
      logout,
      
      // チャット管理
      chatHistory,
      currentChat,
      currentChatId,
      selectedModel,
      models,
      filteredHistory,
      bookmarkedChats,
      isCurrentChatBookmarked,
      searchQuery,
      createNewChat,
      loadChat,
      confirmDeleteChat,
      deleteChat,
      toggleBookmark,
			downloadChat,
      
      // メッセージ関連
			copyMessageContent,
      messageText,
      isGenerating,
			streamEnabled,
      canSendMessage,
      sendMessage,
      startEditMessage,
      cancelEditMessage,
      saveEditMessage,
      resendMessage,
      deleteMessage,
      cancelGeneration,
      editingMessageId,
      editingMessageText,
      
      // UI関連
      messagesContainer,
      messageInput,
      resizeTextarea,
      adjustEditTextarea,
      scrollToBottom,
      showToastMessage,
      renderMarkdown,
      handleMessageContentClick,
      handleTab,
      handleShiftTab,
      handleEditTab,
      handleEditShiftTab,
      formatTimestamp,
			isSidebarOpen,
			isMobile,
			toggleSidebar,
			closeSidebar,
			loadChatMobile,
			
      // モーダル関連
      showEditTitleModal,
      editTitleText,
      openEditTitleModal,
      saveEditedTitle,
      showDeleteConfirmModal,
      
      // トースト通知
      showToast,
      toastMessage,
      closeToast,
      
      // ファイル関連
			ALLOWED_EXTENSIONS,
			MEDIA_EXTENSIONS,
			EXCEL_EXTENSIONS,
			FILE_SIZE_THRESHOLD,
      fileInput,
      attachments,
      openFileInput,
      handleFileUpload,
      getFileIcon,
      removeAttachment,
			isDraggingOver,
			handleDragOver,
			handleDragLeave,
			handleDragEnter,
			handleDrop
    };
  }
}).mount('#app');
