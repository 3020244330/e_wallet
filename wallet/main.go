package main

import (
	"awesomeProject/util"
	"bytes"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net/http"
	"net/mail"
	"path/filepath"
	"time"
)

var db *gorm.DB

type User struct {
	ID           uint   `gorm:"primary_key"`
	Email        string `gorm:"email"`
	PhoneNumber  string `gorm:"unique_index;not null"`
	PasswordHash string `gorm:"not null"`
	PayPassword  string `json:"pay_password"`
	LastLoginIP  string `gorm:"not null"`
}
type SignInRecord struct {
	ID         uint      `gorm:"primary_key"`
	UserID     uint      `gorm:"not null;unique_index"`
	SignInDate time.Time `gorm:"not null"`
}

type Transfer struct {
	ID           int
	FromWalletID int       // 转出钱包id
	ToWalletID   int       // 转入钱包id
	Amount       float64   // 转账金额
	Message      string    // 转账留言
	CreateTime   time.Time // 转账时间
}

type UserLoginRequest struct {
	PhoneNumber string `json:"phone_number" binding:"required,len=11"`
	Password    string `json:"password" binding:"required"`
	IP          string `json:"-"`
}

type UserRegisterRequest struct {
	Email       string `json:"email"  binding:"required"`
	PhoneNumber string `json:"phone_number" binding:"required,len=11"`
	Password    string `json:"password" binding:"required"`
}

type UserRechargeRequest struct {
	Amount float64 `json:"amount" binding:"required"`
}

type UserWithDrawRequest struct {
	Amount      float64 `json:"amount" binding:"required"`
	PayPassword string  `json:"pay_password" binding:"required"`
	BankAccount string  `json:"bank_account" binding:"required"`
}

type UserSetPayPasswordRequest struct {
	PayPassword string `json:"pay_password" binding:"required"`
}

type UserForgotPasswordRequest struct {
	Email string `json:"email" binding:"required"`
}

func (u *User) Register(req UserRegisterRequest) error {
	u.PasswordHash = util.HashPassword(req.Password)
	return db.Create(u).Error
}

func (u *User) Login(request *UserLoginRequest) error {
	if u.LastLoginIP != "" && u.LastLoginIP != request.IP {
		return errors.New("此次登录IP与上次登录IP地址不同，请查看登录日志")
	}
	if !util.CheckPasswordHash(request.Password, u.PasswordHash) {
		return errors.New("手机号或密码错误")
	}
	u.LastLoginIP = request.IP
	return db.Save(u).Error
}

func (u *User) SetPayPassword(payPassword string) error {
	if u.PasswordHash == util.HashPassword(payPassword) {
		return fmt.Errorf("支付密码不能与登录密码相同")
	}
	if len(payPassword) != 6 || isConsecutive(payPassword) {
		return fmt.Errorf("支付密码需要设置为不连续的6位数字")
	}
	u.PayPassword = payPassword
	return nil
}
func (u *User) IsPayPasswordSet(payPassword string) bool {
	return u.PayPassword == payPassword
}

type Avatar struct {
	ID       uint   `gorm:"primary_key"`
	UserID   uint   `gorm:"not null"`
	Filename string `gorm:"not null"`
}

func UploadAvatar(c *gin.Context, userID uint) error {
	file, err := c.FormFile("avatar")
	if err != nil {
		return err
	}

	if file.Size > 512*1024 {
		return errors.New("文件大小不能超过512k")
	}

	filename := fmt.Sprintf("avatar_%d_%s", userID, filepath.Base(file.Filename))

	// 保存头像文件到服务器
	if err := c.SaveUploadedFile(file, filename); err != nil {
		return err
	}

	avatar := &Avatar{
		UserID:   userID,
		Filename: filename,
	}
	err = db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"filename"}),
	}).Create(&avatar).Error

	return err
}

var jwtSecret = []byte("secret_key")

func GenerateToken(user *User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":           user.ID,
		"phone_number": user.PhoneNumber,
		"exp":          time.Now().Add(time.Hour * 24).Unix(),
	})

	return token.SignedString(jwtSecret)
}

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.Request.Header.Get("Authorization")
		if tokenStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "请登录"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "认证失败："})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("userID", claims["id"])
			c.Set("phoneNumber", claims["phone_number"])
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token无效"})
			c.Abort()
			return
		}

		c.Next()
	}
}

type Transaction struct {
	ID          int
	WalletID    int       // 钱包id
	Type        string    // "recharge" 或 "withdraw"
	Amount      float64   // 金额
	HandingFee  float64   // 手续费
	BankAccount string    // 账户
	CreateTime  time.Time // 时间
}

type Wallet struct {
	ID            int
	UserID        int
	Balance       float64
	TotalRecharge float64
}

// 充值
func (w *Wallet) Recharge(amount float64, feePercent float64, db *gorm.DB) {
	handingFee := amount * feePercent
	w.Balance += amount - handingFee
	w.TotalRecharge += amount
	db.Save(w)
	db.Create(&Transaction{WalletID: w.ID, Type: "recharge", Amount: amount, HandingFee: handingFee, CreateTime: time.Now()})
}

// 退款
func (w *Wallet) Withdraw(amount float64, bankAccount string, db *gorm.DB) error {
	if w.Balance < amount {
		return fmt.Errorf("余额不足")
	}
	w.Balance -= amount
	db.Save(w)
	db.Create(&Transaction{WalletID: w.ID, Type: "withdraw", Amount: amount, BankAccount: bankAccount, CreateTime: time.Now()})
	return nil
}

// 转账
func (w *Wallet) Transfer(toWalletID int, amount float64, message string, db *gorm.DB) error {
	if w.Balance < amount {
		return fmt.Errorf("余额不足")
	}
	w.Balance -= amount
	db.Save(w)

	var toWallet Wallet
	if err := db.First(&toWallet, toWalletID).Error; err != nil {
		return fmt.Errorf("没有找到该钱包id")
	}
	toWallet.Balance += amount
	db.Save(&toWallet)

	db.Create(&Transfer{FromWalletID: w.ID, ToWalletID: toWalletID, Amount: amount, Message: message, CreateTime: time.Now()})
	return nil
}

// 获取充值费率
func getFeePercent(totalRecharge float64) float64 {
	if totalRecharge <= 100 {
		return 0
	} else if totalRecharge <= 1000 {
		return 0.05
	} else {
		return 0.03
	}
}

// 是否连续
func isConsecutive(password string) bool {
	for i := 0; i < len(password)-1; i++ {
		if password[i]+1 == password[i+1] {
			return true
		}
	}
	return false
}

func main() {
	dsn := "root:Qwer1234.@tcp(127.0.0.1:3306)/operation?charset=utf8mb4&parseTime=True&loc=Local"
	db, _ = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	db.AutoMigrate(&User{}, &Avatar{}, &Wallet{}, &Transaction{}, &SignInRecord{}, &Transfer{})
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "请使用接口调试工具调试"})
	})
	// 注册路由
	r.POST("/register", func(c *gin.Context) {
		var req UserRegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}

		// 验证邮箱是否合法
		if _, err := mail.ParseAddress(req.Email); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱不合法"})
			return
		}

		// 验证密码强度
		if err := util.ValidatePassword(req.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user := &User{
			PhoneNumber: req.PhoneNumber,
		}
		if err := user.Register(req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "注册成功"})
	})

	// 登录路由
	r.POST("/login", func(c *gin.Context) {
		var req UserLoginRequest
		req.IP = util.GetClientIP(c)
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}

		user := &User{
			PhoneNumber: req.PhoneNumber,
		}
		// 根据手机号码获取用户
		db.Where("phone_number = ?", req.PhoneNumber).First(&user)

		// 检查登录信息
		if err := user.Login(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}

		// 生成JWT Token
		token, err := GenerateToken(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成Token失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "登录成功", "token": token})
	})

	// 头像上传路由
	r.POST("/upload-avatar", JWTAuth(), func(c *gin.Context) {
		userID, _ := c.Get("userID")

		if err := UploadAvatar(c, uint(userID.(float64))); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "头像上传成功"})
	})

	// 开通钱包
	r.POST("/open_wallet", JWTAuth(), func(c *gin.Context) {
		userID, _ := c.Get("userID")
		var wallet Wallet
		if db.First(&wallet, "user_id = ?", userID).Error != nil {
			db.Create(&Wallet{UserID: int(userID.(float64)), Balance: 0})
			c.JSON(http.StatusOK, "Wallet have been opened")
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "钱包已经开通成功了"})
		return
	})
	// 充值路由
	r.POST("/recharge", JWTAuth(), func(c *gin.Context) {
		userID, _ := c.Get("userID")
		var req UserRechargeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}

		var wallet Wallet
		if db.First(&wallet, "user_id = ?", userID).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found wallet"})
			return
		}

		feePercent := getFeePercent(req.Amount)
		wallet.Recharge(req.Amount, feePercent, db)

		c.JSON(http.StatusOK, gin.H{"message": "Recharge successful", "balance": wallet.Balance})
	})

	// 设置支付密码
	r.POST("/set_pay_password", JWTAuth(), func(c *gin.Context) {
		userID, _ := c.Get("userID")
		var req UserSetPayPasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}
		var user User
		if db.First(&user, userID).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		if err := user.SetPayPassword(req.PayPassword); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		db.Save(&user)
		c.JSON(http.StatusOK, gin.H{"message": "Pay password set successfully"})
	})

	// 提现路由
	r.POST("/withdraw", JWTAuth(), func(c *gin.Context) {

		var req UserWithDrawRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}
		userID, _ := c.Get("userID")
		var wallet Wallet
		if db.First(&wallet, "user_id = ?", userID).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		var user User
		if db.First(&user, userID).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		if !user.IsPayPasswordSet(req.PayPassword) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect pay password"})
			return
		}

		if err := wallet.Withdraw(req.Amount, req.BankAccount, db); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Withdraw successful", "balance": wallet.Balance})
	})

	r.GET("/export", JWTAuth(), func(c *gin.Context) {
		userID, _ := c.Get("userID")

		var wallet Wallet
		if db.First(&wallet, "user_id = ?", userID).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found wallet"})
			return
		}

		var trans []Transaction

		startTime := c.DefaultQuery("start_time", "0001-01-01 00:00:00")
		endTime := c.DefaultQuery("end_time", "9999-12-31 23:59:59")

		if db.Where("wallet_id = ? AND create_time >= ? AND create_time <= ?", wallet.ID, startTime, endTime).Find(&trans).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
			return
		}

		f := excelize.NewFile()
		f.SetCellValue("Sheet1", "A1", "Type")
		f.SetCellValue("Sheet1", "B1", "Amount")
		f.SetCellValue("Sheet1", "C1", "CreateTime")
		f.SetCellValue("Sheet1", "D1", "BankAccount")
		f.SetCellValue("Sheet1", "E1", "HandingFee")
		for i, t := range trans {
			f.SetCellValue("Sheet1", fmt.Sprintf("A%d", i+2), t.Type)
			f.SetCellValue("Sheet1", fmt.Sprintf("B%d", i+2), t.Amount)
			f.SetCellValue("Sheet1", fmt.Sprintf("C%d", i+2), t.CreateTime.Format("2006-01-02 15:04:05"))
			f.SetCellValue("Sheet1", fmt.Sprintf("D%d", i+2), t.BankAccount)
			f.SetCellValue("Sheet1", fmt.Sprintf("E%d", i+2), t.HandingFee)
		}

		// 将Excel文件保存到缓冲区中
		var buf bytes.Buffer
		if err := f.Write(&buf); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write excel data"})
			return
		}

		// 将Excel文件作为响应返回
		c.Header("Content-Type", "application/octet-stream")
		c.Header("Content-Disposition", "attachment; filename=transactions.xlsx")
		c.Data(http.StatusOK, "application/octet-stream", buf.Bytes())
	})

	// 查询流水路由
	r.GET("/query_trans", JWTAuth(), func(c *gin.Context) {
		userID, _ := c.Get("userID")

		var wallet Wallet
		if db.First(&wallet, "user_id = ?", userID).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found wallet"})
			return
		}

		var trans []Transaction

		startTime := c.DefaultQuery("start_time", "0001-01-01 00:00:00")
		endTime := c.DefaultQuery("end_time", "9999-12-31 23:59:59")

		if db.Where("wallet_id = ? AND create_time >= ? AND create_time <= ?", wallet.ID, startTime, endTime).Find(&trans).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"transactions": trans})
	})

	r.POST("/forgot_password", func(c *gin.Context) {
		var req UserForgotPasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}

		// 验证邮箱是否合法
		if _, err := mail.ParseAddress(req.Email); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱不合法"})
			return
		}

		var user User
		result := db.Where("email = ?", req.Email).First(&user)

		if result.Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "用户未找到"})
			return
		}

		tempPassword := util.GenerateTempPassword()

		// sendTempPasswordToEmail(req.PhoneNumber, tempPassword)

		user.PasswordHash = util.HashPassword(tempPassword)
		db.Save(&user)

		c.JSON(http.StatusOK, gin.H{"message": "临时密码已发送至您的邮箱，请注意查收， 由于没有实现邮箱接口，现在直接返回信息，手机号: " + user.PhoneNumber + "密码:" + tempPassword})
	})
	r.POST("/daily_sign_in", JWTAuth(), func(c *gin.Context) {
		userID, _ := c.Get("userID")

		var signInRecord SignInRecord
		result := db.Where("user_id = ? AND date(sign_in_date) = ?", userID, time.Now().Format("2006-01-02")).First(&signInRecord)

		if result.Error == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "您今天已经签到过了"})
			return
		}

		redPacketAmount := util.GenerateRedPacketAmount()

		var wallet Wallet
		db.First(&wallet, "user_id = ?", userID)

		wallet.Recharge(redPacketAmount, 0, db)

		signInRecord = SignInRecord{
			UserID:     uint(userID.(float64)),
			SignInDate: time.Now(),
		}
		db.Create(&signInRecord)

		c.JSON(http.StatusOK, gin.H{"message": "签到成功，已领取红包", "red_packet_amount": redPacketAmount, "balance": wallet.Balance})
	})

	// 转账路由
	r.POST("/transfer", JWTAuth(), func(c *gin.Context) {
		type transferRequest struct {
			ToWalletID int     `json:"to_wallet_id" binding:"required"`
			Amount     float64 `json:"amount" binding:"required"`
			Message    string  `json:"message"`
		}
		var req transferRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid param"})
			return
		}
		userID, _ := c.Get("userID")
		var wallet Wallet
		if db.First(&wallet, "user_id = ?", userID).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		if wallet.ID == req.ToWalletID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "不能转给自己"})
			return
		}

		if err := wallet.Transfer(req.ToWalletID, req.Amount, req.Message, db); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Transfer successful", "balance": wallet.Balance})
	})

	r.Run(":8080")
}
