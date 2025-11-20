-- about table
CREATE TABLE about (
    teamNumber INT UNIQUE,
    versionNumber INT,
    releaseDate VARCHAR(255),
    productName VARCHAR(255),
    productDescription VARCHAR(255)
);

-- admins table
CREATE TABLE admins (
    username VARCHAR(50) NOT NULL PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    address VARCHAR(255),
    phone VARCHAR(20),
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE,
    profile_picture VARCHAR(255),
    failed_attempts INT DEFAULT 0,
    locked_until DATETIME,
    disabled TINYINT(1) DEFAULT 0, 
    disabled_by_admin TINYINT(1) DEFAULT 0, 
    receive_emails TINYINT(1) DEFAULT 1,
    login_email TINYINT(1) DEFAULT 1,
    sponsor_locked_email TINYINT(1) DEFAULT 1
);


-- auditLogs table
CREATE TABLE auditLogs (
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    action VARCHAR(255) NOT NULL,
    description VARCHAR(255) NOT NULL, 
    user_id VARCHAR(255)
);

-- Table: auth_group
CREATE TABLE auth_group (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(150) NOT NULL UNIQUE
);

-- Table: auth_group_permissions
CREATE TABLE auth_group_permissions (
    id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    group_id INT NOT NULL,
    permission_id INT NOT NULL,
    KEY (group_id),
    KEY (permission_id)
);

-- Table: auth_permission
CREATE TABLE auth_permission (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    content_type_id INT NOT NULL,
    codename VARCHAR(100) NOT NULL,
    KEY (content_type_id)
);

-- Table: auth_user
CREATE TABLE auth_user (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    password VARCHAR(128) NOT NULL,
    last_login DATETIME(6),
    is_superuser TINYINT(1) NOT NULL,
    username VARCHAR(150) NOT NULL UNIQUE,
    first_name VARCHAR(150) NOT NULL,
    last_name VARCHAR(150) NOT NULL,
    email VARCHAR(254) NOT NULL,
    is_staff TINYINT(1) NOT NULL,
    is_active TINYINT(1) NOT NULL,
    date_joined DATETIME(6) NOT NULL
);

-- Table: auth_user_groups
CREATE TABLE auth_user_groups (
    id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    group_id INT NOT NULL,
    KEY (user_id),
    KEY (group_id)
);

-- Table: auth_user_user_permissions
CREATE TABLE auth_user_user_permissions (
    id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    permission_id INT NOT NULL,
    KEY (user_id),
    KEY (permission_id)
);

-- Table: cart_items
CREATE TABLE cart_items (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    driver_username VARCHAR(64) NOT NULL,
    product_id INT NOT NULL,
    sponsor VARCHAR(50) NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY (driver_username),
    KEY (product_id)
);

-- Table: django_admin_log
CREATE TABLE django_admin_log (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    action_time DATETIME(6) NOT NULL,
    object_id LONGTEXT,
    object_repr VARCHAR(200) NOT NULL,
    action_flag SMALLINT UNSIGNED NOT NULL,
    change_message LONGTEXT NOT NULL,
    content_type_id INT,
    user_id INT NOT NULL,
    KEY (content_type_id),
    KEY (user_id)
);

-- Table: django_content_type
CREATE TABLE django_content_type (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    app_label VARCHAR(100) NOT NULL,
    model VARCHAR(100) NOT NULL,
    KEY (app_label)
);

-- Table: django_migrations
CREATE TABLE django_migrations (
    id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    app VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    applied DATETIME(6) NOT NULL
);

-- Table: django_session
CREATE TABLE django_session (
    session_key VARCHAR(40) NOT NULL PRIMARY KEY,
    session_data LONGTEXT NOT NULL,
    expire_date DATETIME(6) NOT NULL,
    KEY (expire_date)
);

-- Table: driverApplications
CREATE TABLE driverApplications (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    driverUsername VARCHAR(255),
    sponsor VARCHAR(255),
    status ENUM('pending','accepted','rejected','withdrawn','dropped') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Table: driverPoints
CREATE TABLE driverPoints (
    username VARCHAR(255),
    points INT
);


-- Table: driver_sponsor_points
CREATE TABLE driver_sponsor_points (
    driver_username VARCHAR(50) NOT NULL,
    sponsor VARCHAR(50) NOT NULL,
    points INT NOT NULL DEFAULT 0,
    PRIMARY KEY (driver_username, sponsor)
);

-- Table: drivers
CREATE TABLE drivers (
    username VARCHAR(50) NOT NULL PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    address VARCHAR(255),
    phone VARCHAR(20),
    points INT DEFAULT 0,
    tier VARCHAR(50) DEFAULT 'Bronze',
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    profile_picture VARCHAR(255),
    twitter VARCHAR(255),
    facebook VARCHAR(255),
    instagram VARCHAR(255),
    vehicle_make VARCHAR(100),
    vehicle_model VARCHAR(100),
    vehicle_year INT,
    failed_attempts INT DEFAULT 0,
    locked_until DATETIME,
    disabled TINYINT(1) DEFAULT 0,
    disabled_by_admin TINYINT(1) DEFAULT 0,
    receive_emails TINYINT(1) DEFAULT 1,
    login_email TINYINT(1) DEFAULT 1,
    low_balance_email TINYINT(1) DEFAULT 1,
    points_added_email TINYINT(1) DEFAULT 1,
    points_removed_email TINYINT(1) DEFAULT 1,
    driver_dropped_email TINYINT(1) DEFAULT 1,
    spend_points_email TINYINT(1) DEFAULT 1,
    favorite_back_in_stock_email TINYINT(1) DEFAULT 1,
    new_item_email TINYINT(1) DEFAULT 1,
    order_placed_email TINYINT(1) DEFAULT 1
);

-- Table: favorites
CREATE TABLE favorites (
    driver_username VARCHAR(64) NOT NULL,
    product_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (driver_username, product_id)
);

-- Table: feedback
CREATE TABLE feedback (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_role VARCHAR(50) NOT NULL,
    feedback_text TEXT NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: loginAttempts
CREATE TABLE loginAttempts (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    role ENUM('driver','sponsor','admin') NOT NULL,
    ip_address VARCHAR(45),
    successful TINYINT(1) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: notificationAlerts
CREATE TABLE notificationAlerts (
    notification_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table: orders
CREATE TABLE orders (
    order_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    product_id INT NOT NULL,
    sponsor VARCHAR(50) NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    delivery_address VARCHAR(255),
    reward_description VARCHAR(255) NOT NULL,
    order_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    point_cost INT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Processing'
);


-- Table: passwordResets
CREATE TABLE passwordResets (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    role ENUM('driver','sponsor','admin') NOT NULL,
    token VARCHAR(100) NOT NULL,
    expiration DATETIME NOT NULL,
    used TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: products
CREATE TABLE products (
    product_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description MEDIUMTEXT,
    sponsor VARCHAR(50),
    points_cost INT NOT NULL,
    quantity INT DEFAULT 0,
    source_type VARCHAR(16) NOT NULL DEFAULT 'local',
    ebay_item_id VARCHAR(64),
    image_url VARCHAR(512),
    price_value DECIMAL(10,2),
    price_currency VARCHAR(8)
);


-- Table: recurring_reports
CREATE TABLE recurring_reports (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    report_type VARCHAR(100) NOT NULL,
    sponsor_id VARCHAR(50) NOT NULL,
    day_of_week ENUM('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday') NOT NULL,
    enabled TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- Table: reports
CREATE TABLE reports (
    report_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    report_name VARCHAR(255) NOT NULL,
    report_data TEXT,
    generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- Table: reviews
CREATE TABLE reviews (
    review_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    product_id INT NOT NULL,
    driver_username VARCHAR(50) NOT NULL,
    rating TINYINT NOT NULL,
    title VARCHAR(120),
    body TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    KEY (product_id),
    KEY (driver_username)
);


-- Table: simulation_rules
CREATE TABLE simulation_rules (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    type ENUM('add_driver','remove_driver','add_points','remove_points') NOT NULL,
    driver_username VARCHAR(255),
    points INT,
    schedule VARCHAR(255) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- Table: sponsor
CREATE TABLE sponsor (
    username VARCHAR(50) NOT NULL PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    address VARCHAR(255),
    phone VARCHAR(20),
    organization VARCHAR(100),
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE,
    profile_picture VARCHAR(255),
    twitter VARCHAR(255),
    facebook VARCHAR(255),
    instagram VARCHAR(255),
    company_link VARCHAR(255),
    failed_attempts INT DEFAULT 0,
    locked_until DATETIME,
    company_logo VARCHAR(255),
    min_points INT DEFAULT 0,
    max_points INT DEFAULT 10000,
    disabled TINYINT(1) DEFAULT 0,
    disabled_by_admin TINYINT(1) DEFAULT 0,
    receive_emails TINYINT(1) DEFAULT 1,
    login_email TINYINT(1) DEFAULT 1,
    driver_app_email TINYINT(1) DEFAULT 1
);


-- Table: sponsor_field_requirements
CREATE TABLE sponsor_field_requirements (
    sponsor_username VARCHAR(100) NOT NULL,
    field_name VARCHAR(50) NOT NULL,
    is_required TINYINT(1) DEFAULT 0,
    PRIMARY KEY (sponsor_username, field_name)
);
