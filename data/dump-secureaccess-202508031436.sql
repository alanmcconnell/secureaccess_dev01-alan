-- MySQL dump 10.13  Distrib 8.0.19, for Win64 (x86_64)
--
-- Host: localhost    Database: secureaccess2
-- ------------------------------------------------------
-- Server version	8.0.42

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `sa_audit_log`
--

DROP TABLE IF EXISTS `sa_audit_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sa_audit_log` (
  `log_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `jwt_token_id` int DEFAULT NULL,
  `action_type` varchar(100) NOT NULL,
  `target_account_service` varchar(255) DEFAULT NULL,
  `target_resource` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text,
  `timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `success_status` tinyint(1) NOT NULL,
  `error_message` text,
  `additional_data` json DEFAULT NULL,
  PRIMARY KEY (`log_id`),
  KEY `jwt_token_id` (`jwt_token_id`),
  KEY `idx_user_timestamp` (`user_id`,`timestamp`),
  KEY `idx_action_type` (`action_type`),
  KEY `idx_timestamp` (`timestamp`),
  CONSTRAINT `audit_log_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `sa_users` (`user_id`) ON DELETE SET NULL,
  CONSTRAINT `audit_log_ibfk_2` FOREIGN KEY (`jwt_token_id`) REFERENCES `sa_jwt_tokens` (`token_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sa_encryption_keys`
--

DROP TABLE IF EXISTS `sa_encryption_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sa_encryption_keys` (
  `key_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `encrypted_master_key` text NOT NULL,
  `key_derivation_salt` varchar(255) NOT NULL,
  `key_derivation_iterations` int DEFAULT '100000',
  `creation_timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `key_version` int DEFAULT '1',
  `is_active` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`key_id`),
  KEY `idx_encryption_keys_user` (`user_id`,`is_active`),
  CONSTRAINT `encryption_keys_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `sa_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sa_jwt_blacklist`
--

DROP TABLE IF EXISTS `sa_jwt_blacklist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sa_jwt_blacklist` (
  `blacklist_id` int NOT NULL AUTO_INCREMENT,
  `token_hash` varchar(255) NOT NULL,
  `jti` varchar(255) NOT NULL,
  `expiration_timestamp` timestamp NOT NULL,
  `reason_for_blacklisting` varchar(255) DEFAULT NULL,
  `timestamp_blacklisted` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`blacklist_id`),
  KEY `idx_jti_blacklist` (`jti`),
  KEY `idx_expiration_blacklist` (`expiration_timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sa_jwt_tokens`
--

DROP TABLE IF EXISTS `sa_jwt_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sa_jwt_tokens` (
  `token_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `token_type` enum('access','refresh') NOT NULL,
  `jwt_token_hash` varchar(255) NOT NULL,
  `jti` varchar(255) NOT NULL,
  `claims_summary` json DEFAULT NULL,
  `issue_timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `expiration_timestamp` timestamp NOT NULL,
  `revoked_status` tinyint(1) DEFAULT '0',
  `revocation_timestamp` timestamp NULL DEFAULT NULL,
  `token_family_id` varchar(255) DEFAULT NULL,
  `device_info` text,
  `ip_address` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`token_id`),
  UNIQUE KEY `jti` (`jti`),
  KEY `idx_jti` (`jti`),
  KEY `idx_user_type` (`user_id`,`token_type`),
  KEY `idx_expiration` (`expiration_timestamp`),
  KEY `idx_family` (`token_family_id`),
  CONSTRAINT `jwt_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `sa_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sa_stored_accounts`
--

DROP TABLE IF EXISTS `sa_stored_accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sa_stored_accounts` (
  `account_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `application_id` int NOT NULL,
  `account_username` varchar(255) NOT NULL,
  `account_email` varchar(255) DEFAULT NULL,
  `encrypted_password` text NOT NULL,
  `account_category` varchar(100) DEFAULT NULL,
  `account_folder` varchar(100) DEFAULT NULL,
  `notes` text,
  `date_created` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `date_modified` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `date_last_accessed` timestamp NULL DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`account_id`),
  KEY `idx_stored_accounts_user` (`user_id`),
  KEY `idx_stored_accounts_app` (`application_id`),
  CONSTRAINT `stored_accounts_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `sa_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sa_user_preferences`
--

DROP TABLE IF EXISTS `sa_user_preferences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sa_user_preferences` (
  `preference_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `password_length` int DEFAULT '12',
  `password_include_uppercase` tinyint(1) DEFAULT '1',
  `password_include_lowercase` tinyint(1) DEFAULT '1',
  `password_include_numbers` tinyint(1) DEFAULT '1',
  `password_include_symbols` tinyint(1) DEFAULT '1',
  `password_exclude_ambiguous` tinyint(1) DEFAULT '1',
  `security_timeout_minutes` int DEFAULT '15',
  `auto_logout_enabled` tinyint(1) DEFAULT '1',
  `notification_login_enabled` tinyint(1) DEFAULT '1',
  `notification_password_access` tinyint(1) DEFAULT '0',
  `theme_preference` varchar(20) DEFAULT 'light',
  `language_preference` varchar(10) DEFAULT 'en',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`preference_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `user_preferences_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `sa_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sa_user_sessions`
--

DROP TABLE IF EXISTS `sa_user_sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sa_user_sessions` (
  `session_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `session_token` varchar(500) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `device_info` text,
  `user_agent` text,
  `login_timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `expiration_timestamp` timestamp NOT NULL,
  `active_status` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`session_id`),
  KEY `idx_session_token` (`session_token`),
  KEY `idx_user_active` (`user_id`,`active_status`),
  CONSTRAINT `user_sessions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `sa_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sa_users`
--

DROP TABLE IF EXISTS `sa_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sa_users` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `first_name` varchar(100) NOT NULL,
  `last_name` varchar(100) NOT NULL,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `master_password_hash` varchar(255) NOT NULL,
  `salt` varchar(255) NOT NULL,
  `account_creation_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login_timestamp` timestamp NULL DEFAULT NULL,
  `account_status` enum('active','inactive','locked') DEFAULT 'active',
  `security_question_1` text,
  `security_answer_1_hash` varchar(255) DEFAULT NULL,
  `security_question_2` text,
  `security_answer_2_hash` varchar(255) DEFAULT NULL,
  `two_factor_enabled` tinyint(1) DEFAULT '0',
  `two_factor_secret` varchar(255) DEFAULT NULL,
  `jwt_secret_version` int DEFAULT '1',
  `refresh_token_rotation_enabled` tinyint(1) DEFAULT '1',
  `token_expiration_minutes` int DEFAULT '60',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`),
  KEY `idx_users_email` (`email`),
  KEY `idx_users_username` (`username`),
  KEY `idx_users_status` (`account_status`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping routines for database 'secureaccess'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-08-03 14:36:35
