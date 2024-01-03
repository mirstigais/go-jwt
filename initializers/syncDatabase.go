package initializers

import (
	"mirstigais/go-jwt/models"
)

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
