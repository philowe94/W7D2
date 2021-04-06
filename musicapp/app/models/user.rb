class User < ApplicationRecord

    after_initialize :ensure_session_token

    attr_reader :password

    def self.find_by_credentials(email, password)
        user = User.find_by(email: email)
        user_pass_digest = user.password_digest
        if user.nil? == false
            return user if BCrypt::Password.new(user_pass_digest).is_password?(password)
        end
    end

    def self.generate_session_token
        SecureRandom.urlsafe_base64(16)
    end

    def reset_session_token
        self.session_token = User.generate_session_token
        self.save!
        self.session_token
    end

    def password=(password)
        self.password_digest = BCrypt::Password.create(password)
    end

    private

    def ensure_session_token
        self.session_token ||= User.generate_session_token
    end
end