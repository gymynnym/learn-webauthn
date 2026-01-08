package main

import (
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

const ( // Gin 서버 설정
	HOSTNAME = "localhost"
	PORT     = ":8080"
)

var (
	userDB                 = map[string]*User{}                 // in-memory DB (username -> User)
	registrationCacheStore = map[string]*RegistrationCache{}    // in-memory registration 임시 저장소 (uesrname -> RegistrationCache)
	loginSessionStore      = map[string]*webauthn.SessionData{} // in-memory login 임시 저장소(username -> SessionData)
	webAuthn               *webauthn.WebAuthn
)

func initWebAuthn() { // WebAuthn 객체 초기화
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		// Relying Party 설정
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

	// user 존재 여부 확인
	if _, exists := userDB[username]; exists {
		c.JSON(409, gin.H{"error": "User already exists"})
		return
	}

	// 사용자 객체 생성
	user := User{
		ID:   uint64(len(userDB) + 1),
		Name: username,
	}

	// 등록#2: 챌린지 및 옵션 생성
	options, sessionData, err := webAuthn.BeginRegistration(&user)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to begin registration"})
		return
	}

	// 임시 저장소에 세션 데이터 및 사용자 정보 저장
	registrationCacheStore[username] = &RegistrationCache{
		SessionData: *sessionData,
		PendingUser: &user,
	}
	c.JSON(200, options)
}

func finishRegistration(c *gin.Context) {
	username := c.Param("username")

	// 세션 데이터 및 사용자 정보 가져오기
	cache, exists := registrationCacheStore[username]
	if !exists {
		c.JSON(400, gin.H{"error": "No session data found"})
		return
	}

	// 등록#6: 검증
	credential, err := webAuthn.FinishRegistration(cache.PendingUser, cache.SessionData, c.Request)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to finish registration"})
		return
	}

	// 등록#6: 저장
	user := cache.PendingUser
	user.Credentials = append(user.Credentials, *credential) // 새로운 자격 증명 추가
	userDB[username] = user                                  // 사용자 DB에 저장
	delete(registrationCacheStore, username)                 // 임시 저장소 정리

	c.JSON(200, gin.H{"status": "Registration successful"})
}

func beginLogin(c *gin.Context) {
	username := c.Param("username")

	// user 가져오기 및 존재 여부 확인
	user, exists := userDB[username]
	if !exists {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	// 인증#2: 챌린지 생성
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

	// user 가져오기 및 존재 여부 확인
	user, exists := userDB[username]
	if !exists {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	// 임시 저장소에서 세션 데이터 가져오기
	sessionData, exists := loginSessionStore[username]
	if !exists {
		c.JSON(400, gin.H{"error": "No session data found"})
		return
	}

	// #인증#6: 검증
	credential, err := webAuthn.FinishLogin(user, *sessionData, c.Request)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to finish login"})
		return
	}
	_ = credential // TODO: Credential을 활용한 세션 또는 토큰 발급

	delete(loginSessionStore, username) // 임시 저장소 정리

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
