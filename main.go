package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var (
	users      = make(map[string]string)
	files      = make(map[int]CodeFile)
	comments   = make(map[int][]Comment)
	userTokens = make(map[string]string)
	fileID     = 1
	commentID  = 1
	mu         sync.Mutex
)

var jwtKey = []byte("secret_key")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type CodeFile struct {
	ID       int    `json:"id"`
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

type Comment struct {
	ID        int       `json:"id"`
	FileID    int       `json:"file_id"`
	LineStart int       `json:"line_start"`
	LineEnd   int       `json:"line_end"`
	Username  string    `json:"username"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
}

func CreateAccount(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println("CreateAccount: Bad request -", err)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if _, exists := users[creds.Username]; exists {
		w.WriteHeader(http.StatusConflict)
		log.Println("CreateAccount: Conflict - Username already exists")
		return
	}
	users[creds.Username] = creds.Password
	w.WriteHeader(http.StatusCreated)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println("Login: Bad request -", err)
		return
	}
	mu.Lock()
	password, ok := users[creds.Username]
	mu.Unlock()
	if !ok || password != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("Login: Unauthorized - Invalid credentials")
		return
	}
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Login: Internal server error -", err)
		return
	}
	mu.Lock()
	userTokens[creds.Username] = tokenString
	mu.Unlock()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func UploadFile(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("UploadFile: Missing authorization header")
		return
	}
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("UploadFile: Unauthorized access -", err)
		return
	}

	var file CodeFile
	err = json.NewDecoder(r.Body).Decode(&file)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println("UploadFile: Bad request -", err)
		return
	}

	mu.Lock()
	file.ID = fileID
	fileID++
	files[file.ID] = file
	mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(file)
	log.Println("UploadFile: File uploaded -", file)
}

func GetFiles(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	var fileList []CodeFile
	for _, file := range files {
		fileList = append(fileList, file)
	}
	json.NewEncoder(w).Encode(fileList)
}

func AddComment(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("AddComment: Missing authorization header")
		return
	}
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("AddComment: Unauthorized access -", err)
		return
	}

	var comment Comment
	err = json.NewDecoder(r.Body).Decode(&comment)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println("AddComment: Bad request -", err)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	// Check for overlapping comments
	for _, existingComments := range comments[comment.FileID] {
		if (comment.LineStart >= existingComments.LineStart && comment.LineStart <= existingComments.LineEnd) ||
			(comment.LineEnd >= existingComments.LineStart && comment.LineEnd <= existingComments.LineEnd) ||
			(existingComments.LineStart >= comment.LineStart && existingComments.LineStart <= comment.LineEnd) ||
			(existingComments.LineEnd >= comment.LineStart && existingComments.LineEnd <= comment.LineEnd) {
			w.WriteHeader(http.StatusConflict)
			log.Println("AddComment: Conflict - Overlapping line range")
			return
		}
	}

	comment.Username = claims.Username
	comment.Timestamp = time.Now()
	comment.ID = commentID
	commentID++
	comments[comment.FileID] = append(comments[comment.FileID], comment)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(comment)
	log.Println("AddComment: Comment added -", comment)
}

func GetComments(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println("GetComments: Bad request -", err)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	fileComments, ok := comments[fileID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		log.Println("GetComments: Not found - No comments for file ID", fileID)
		return
	}
	json.NewEncoder(w).Encode(fileComments)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/create-account", CreateAccount).Methods("POST")
	r.HandleFunc("/login", Login).Methods("POST")
	r.HandleFunc("/upload-file", UploadFile).Methods("POST")
	r.HandleFunc("/files", GetFiles).Methods("GET")
	r.HandleFunc("/comment", AddComment).Methods("POST")
	r.HandleFunc("/comments/{id}", GetComments).Methods("GET")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	log.Fatal(http.ListenAndServe(":8080", r))
}
