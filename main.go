package main

import (
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

const ( // Gin サーバー設定
	HOSTNAME = "localhost"
	PORT     = ":8080"
)

var (
	userDB                 = map[string]*User{}                 // in-memory DB (username -> User)
	registrationCacheStore = map[string]*RegistrationCache{}    // in-memory registration キャッシュストア (username -> RegistrationCache)
	loginSessionStore      = map[string]*webauthn.SessionData{} // in-memory login キャッシュストア (username -> SessionData)
	webAuthn               *webauthn.WebAuthn
)

func initWebAuthn() { // WebAuthn 初期化
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		// Relying Party 情報設定
		RPDisplayName: "Example App",
		RPID:          HOSTNAME,
		RPOrigins:     []string{"http://" + HOSTNAME + PORT},
	})
	if err != nil {
		panic("Failed to initialize WebAuthn: " + err.Error())
	}
}

func beginRegistration(c *gin.Context) {
	username := c.Param("username")

	// ユーザー存在確認
	if _, exists := userDB[username]; exists {
		c.JSON(409, gin.H{"error": "User already exists"})
		return
	}

	// ユーザー生成
	user := User{
		ID:   uint64(len(userDB) + 1),
		Name: username,
	}

	// 登録#2: チャレンジとオプション生成
	options, sessionData, err := webAuthn.BeginRegistration(&user)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to begin registration"})
		return
	}

	// キャッシュストアにセッションデータとユーザー情報を保存
	registrationCacheStore[username] = &RegistrationCache{
		SessionData: *sessionData,
		PendingUser: &user,
	}
	c.JSON(200, options)
}

func finishRegistration(c *gin.Context) {
	username := c.Param("username")

	// セッションデータとユーザー情報取得
	cache, exists := registrationCacheStore[username]
	if !exists {
		c.JSON(400, gin.H{"error": "No session data found"})
		return
	}

	// 登録#6: 検証
	credential, err := webAuthn.FinishRegistration(cache.PendingUser, cache.SessionData, c.Request)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to finish registration"})
		return
	}

	// 登録#6: 保存
	user := cache.PendingUser
	user.Credentials = append(user.Credentials, *credential) // 新しい資格情報を追加
	userDB[username] = user                                  // ユーザーDBに保存
	delete(registrationCacheStore, username)                 // キャッシュストアから削除

	c.JSON(200, gin.H{"status": "Registration successful"})
}

func beginLogin(c *gin.Context) {
	username := c.Param("username")

	// ユーザー取得と存在確認
	user, exists := userDB[username]
	if !exists {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	// 認証#2: チャレンジとオプション生成
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to begin login"})
		return
	}

	loginSessionStore[username] = sessionData
	c.JSON(200, options)
}

func finishLogin(c *gin.Context) {
	username := c.Param("username")

	// ユーザー取得と存在確認
	user, exists := userDB[username]
	if !exists {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	// キャッシュストアからセッションデータ取得
	sessionData, exists := loginSessionStore[username]
	if !exists {
		c.JSON(400, gin.H{"error": "No session data found"})
		return
	}

	// #認証#6: 検証
	credential, err := webAuthn.FinishLogin(user, *sessionData, c.Request)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to finish login"})
		return
	}
	_ = credential // TODO: Credentialを使ったセッションまたはトークン生成

	delete(loginSessionStore, username) // キャッシュストアから削除

	c.JSON(200, gin.H{"status": "Login successful"})
}

func main() {
	initWebAuthn()

	r := gin.Default()

	r.StaticFile("/", "index.html")

	r.GET("/register/begin/:username", beginRegistration)
	r.POST("/register/finish/:username", finishRegistration)
	r.GET("/login/begin/:username", beginLogin)
	r.POST("/login/finish/:username", finishLogin)

	if err := r.Run(PORT); err != nil {
		panic("Failed to start server: " + err.Error())
	}
}
