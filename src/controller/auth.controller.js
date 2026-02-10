const { globalError, ClientError } = require("shokhijakhon-error-handler");
const {
  registerValidator,
  profileVerifiedValidator,
  resendOtpOrForgotPasswordValidator,
  changePasswordValidator,
  loginValidator,
} = require("../utils/validator/auth.validator");
const UserModel = require("../models/User.model");
const { hash, compare } = require("bcrypt");
const otpGenerator = require("../utils/generators/otp.generator");
const emailService = require("../lib/mail.service");
const jwtService = require("../lib/jwt.service");
const logger = require("../lib/winston.service");

module.exports = {
  async REGISTER(req, res) {
    try {
      logger.debug(`REGISTER attempt with data: ${JSON.stringify(req.body)}`);
      let newUser = req.body;
      await registerValidator.validateAsync(newUser);
      let findUser = await UserModel.findOne({ email: newUser.email });
      if (findUser) {
        logger.warn(`REGISTER failed: email already exists: ${newUser.email}`);
        throw new ClientError("User already exists !");
      }
      newUser.password = await hash(newUser.password, 10);
      let { otp, otpTime } = otpGenerator();
      await emailService(newUser.email, otp);
      await UserModel.create({
        ...newUser,
        otp,
        otpTime,
      });
      logger.info(`Code sent to email ${newUser.email}`);
      return res
        .status(201)
        .json({ message: "User successfully registered !", status: 201 });
    } catch (err) {
      logger.error(`REGISTER error: ${err.message}`);
      return globalError(err, res);
    }
  },
  async VERIFY(req, res) {
    try {
      logger.debug(`VERIFY request: ${JSON.stringify(req.body)}`);
      let profileData = req.body;
      await profileVerifiedValidator.validateAsync(profileData);

      let findUser = await UserModel.findOne({ email: profileData.email });
      if (!findUser) {
        logger.warn(`VERIFY failed: user not found (${profileData.email})`);
        throw new ClientError("User not found !", 404);
      }
      let currentDate = Date.now();
      if (currentDate > findUser.otpTime) {
        logger.warn(`VERIFY failed: OTP expired for ${profileData.email}`);
        throw new ClientError("OTP expired !", 400);
      }

      if (profileData.otp != findUser.otp) {
        logger.warn(`VERIFY failed: invalid OTP for ${profileData.email}`);
        throw new ClientError("OTP invalid !", 400);
      }
      await UserModel.findOneAndUpdate(
        { email: profileData.email },
        { is_verified: true },
      );

      logger.info(`Email has been successfully verified: ${data.email}`);
      return res.json({
        message: "Profile successfullt verified",
        status: 200,
      });
    } catch (err) {
      logger.error(`VERIFY error: ${err.message}`);
      return globalError(err, res);
    }
  },
  async RESEND_OTP(req, res) {
    try {
      logger.debug(`RESEND_OTP attempt: ${JSON.stringify(req.body)}`);
      let profileData = req.body;
      await resendOtpOrForgotPasswordValidator.validateAsync(profileData);
      let findUser = await UserModel.findOne({ email: profileData.email });
      if (!findUser || findUser.is_verified) {
        logger.warn(`RESEND_OTP failed: user not found (${profileData.email})`);
        throw new ClientError("User not found or user already activated", 404);
      }
      let { otp, otpTime } = otpGenerator();
      await emailService(profileData.email, otp);
      logger.info(`Code sent to email ${profileData.email}`);
      await UserModel.findOneAndUpdate(
        { email: profileData.email },
        { otp, otpTime },
      );
      return res.json({ message: "OTP successfully resended" });
    } catch (err) {
      logger.error(`RESEND_OTP error: ${err.message}`);
      return globalError(err, res);
    }
  },
  async FORGOT_PASSWORD(req, res) {
    try {
      logger.debug(`FORGOT_PASSWORD request: ${JSON.stringify(req.body)}`);
      let profileData = req.body;
      await resendOtpOrForgotPasswordValidator.validateAsync(profileData);
      let findUser = await UserModel.findOne({ email: profileData.email });
      if (!findUser || findUser.is_verified) {
        logger.warn(
          `FORGOT_PASSWORD failed: user not found (${profileData.email})`,
        );
        throw new ClientError("User not found or user already activated", 404);
      }
      let { otp, otpTime } = otpGenerator();
      await emailService(profileData.email, otp);
      logger.info(`Code sent to email ${profileData.email}`);
      await UserModel.findOneAndUpdate(
        { email: profileData.email },
        { otp, otpTime },
      );
      return res.json({ message: "OTP successfully resended" });
    } catch (err) {
      logger.error(`FORGOT_PASSWORD error: ${err.message}`);
      return globalError(err, res);
    }
  },
  async CHANGE_PASSWORD(req, res) {
    try {
      logger.debug(`CHANGE_PASSWORD attempt for: ${req.body.email}`);
      let profileData = req.body;
      await changePasswordValidator.validateAsync(profileData);
      let findUser = await UserModel.findOne({ email: profileData.email });
      if (!findUser) {
        logger.warn(
          `CHANGE_PASSWORD failed: user not found (${profileData.email})`,
        );
        throw new ClientError("User not found", 404);
      }
      if (!findUser.is_verified) {
        logger.warn(
          `CHANGE_PASSWORD failed: account not verified (${profileData.email})`,
        );
        throw new ClientError("Please verify your account", 400);
      }
      let hash_password = await hash(profileData.new_password, 10);
      await UserModel.findOneAndUpdate(
        { email: profileData.email },
        { password: hash_password },
      );

      logger.info(`Password changed successfully for ${profileData.email}`);
      return res.json({
        message: "Password successfullt changed",
        status: 200,
      });
    } catch (err) {
      logger.error(`CHANGE_PASSWORD error: ${err.message}`);
      return globalError(err, res);
    }
  },
  async LOGIN(req, res) {
    try {
      logger.debug(`LOGIN attempt: ${req.body.email}`);
      let data = req.body;
      await loginValidator.validateAsync(data);
      let findUser = await UserModel.findOne({ email: data.email });
      if (!findUser || !findUser.is_verified) {
        logger.warn(`LOGIN failed: user not found -> ${data.email}`);
        throw new ClientError("User not found or user already activated", 404);
      }
      let checkPassword = await compare(data.password, findUser.password);
      if (!checkPassword) {
        logger.warn(`LOGIN failed: wrong password -> ${data.email}`);
        throw new ClientError("Password or email invalid", 400);
      }
      let accessToken = jwtService.createAccessToken({ sub: findUser.id });
      logger.info(`LOGIN success: ${data.email}`);
      return res.json({
        message: "User successfully logged in",
        status: 200,
        accessToken,
      });
    } catch (err) {
      logger.error(`LOGIN error: ${err.message}`);
      return globalError(err, res);
    }
  },
};
