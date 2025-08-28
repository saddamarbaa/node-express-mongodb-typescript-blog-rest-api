import { NextFunction, Request, RequestHandler, Response } from 'express';
import createHttpError, { InternalServerError } from 'http-errors';
import { SignOptions } from 'jsonwebtoken';

import { AuthenticatedRequestBody, IUser, ResponseT } from '@src/interfaces';
import { environmentConfig } from '@src/configs';
import {
  customResponse,
  deleteFile,
  getProfilePicture,
  getRoleFromEmail,
  sendConfirmResetPasswordEmailTemplate,
  sendEmailVerificationTemplate,
  sendMail,
  sendResetPasswordEmailTemplate
} from '@src/utils';
import Token from '@src/models/Token.model';
import User from '@src/models/User.model';
import { cloudinary, verifyRefreshToken } from '@src/middlewares';
import { AUTHORIZATION_ROLES } from '@src/constants';

export const signupService = async (req: Request, res: Response<ResponseT<null>>, next: NextFunction) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      bio,
      skills,
      profileUrl,
      acceptTerms,
      confirmationCode,
      gender
    } = req.body as IUser;

    // Check if email already exists
    const isEmailExit = await User.findOne({ email: new RegExp(`^${email}$`, 'i') });
    if (isEmailExit) {
      return next(createHttpError(409, `E-Mail address ${email} is already exists, please pick a different one.`));
    }

    // Generate profile picture URL
    const finalUserProfilePic = getProfilePicture(firstName, lastName, gender, profileUrl);

    // Determine role based on email
    const role = getRoleFromEmail(email);

    const finalAcceptTerms =
      acceptTerms ||
      !!(
        environmentConfig?.ADMIN_EMAILS &&
        (JSON.parse(environmentConfig.ADMIN_EMAILS) as string[])?.includes(`${email}`)
      );

    // Create a new user
    const newUser = new User({
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      bio,
      role,
      profileUrl: finalUserProfilePic,
      skills: skills || [],
      confirmationCode,
      acceptTerms: finalAcceptTerms
    });

    // Create and save a new user
    const user = await newUser.save();

    // Create a new token instance for the user
    let token = new Token({ userId: user._id });

    const payload = { userId: user._id };

    // Define secret keys and options for both access and refresh tokens
    const accessTokenSecretKey = environmentConfig.ACCESS_TOKEN_SECRET_KEY as string;
    const refreshTokenSecretKey = environmentConfig.REFRESH_TOKEN_SECRET_KEY as string;

    const accessTokenOptions: SignOptions = {
      expiresIn: environmentConfig.ACCESS_TOKEN_KEY_EXPIRE_TIME,
      issuer: environmentConfig.JWT_ISSUER,
      audience: String(user._id)
    };

    const refreshTokenOptions: SignOptions = {
      expiresIn: environmentConfig.REFRESH_TOKEN_KEY_EXPIRE_TIME,
      issuer: environmentConfig.JWT_ISSUER,
      audience: String(user._id)
    };

    // Generate access and refresh tokens
    const generatedAccessToken = await token.generateToken(payload, accessTokenSecretKey, accessTokenOptions);
    const generatedRefreshToken = await token.generateToken(payload, refreshTokenSecretKey, refreshTokenOptions);

    //  const [accessToken, refreshToken] = await Promise.all([
    //   token.generateToken(payload, ACCESS_TOKEN_SECRET_KEY as string, accessTokenOptions),
    //   token.generateToken(payload, REFRESH_TOKEN_SECRET_KEY as string, refreshTokenOptions)
    // ]);

    // Update token instance with the generated tokens
    token.refreshToken = generatedRefreshToken;
    token.accessToken = generatedAccessToken;

    // Save the token instance
    token = await token.save();

    const verifyEmailLink = `${environmentConfig.WEBSITE_URL}/verify-email?id=${user._id}&token=${token.refreshToken}`;

    // send mail for email verification
    const { data: resendEmailData, error } = await sendMail({
      to: user.email,
      ...sendEmailVerificationTemplate(verifyEmailLink, firstName)
    });

    // ignore email errors for now
    if (error) {
      if (process?.env?.NODE_ENV && process.env.NODE_ENV === 'development') {
        console.log('Sending Email error:', error);
        console.log('Sending Email error:');
      }
    } else if (process?.env?.NODE_ENV && process.env.NODE_ENV === 'development') {
      console.log(`Successfully  send email to ${email}...`);
      console.log(resendEmailData);
    }

    const data = {
      user: {
        accessToken: token.accessToken,
        refreshToken: token.refreshToken,
        verifyEmailLink
      }
    };

    return res.status(201).json(
      customResponse<any>({
        data,
        success: true,
        error: false,
        message: `Auth Signup is success. An Email with Verification link has been sent to your account ${user.email} Please Verify Your Email first or use the email verification lik which is been send with the response body to verfiy your email`,
        status: 201
      })
    );
  } catch (error: any) {
    return next(InternalServerError);
  }
};

export const loginService = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email: new RegExp(`^${email}$`, 'i') })
      .select('+password')
      .exec();

    // 401 Unauthorized
    if (!user) {
      return next(createHttpError(401, 'Auth Failed (Invalid Credentials)'));
    }

    // Compare password
    const isPasswordCorrect = await user.comparePassword(password);

    if (!isPasswordCorrect) {
      return next(createHttpError(401, 'Auth Failed (Invalid Credentials)'));
    }

    let token = await Token.findOne({ userId: user._id });

    if (!token) {
      token = await new Token({ userId: user._id });
      token = await token.save();
    }

    const generatedAccessToken = await token.generateToken(
      {
        userId: user._id
      },
      environmentConfig.ACCESS_TOKEN_SECRET_KEY,
      {
        expiresIn: environmentConfig.ACCESS_TOKEN_KEY_EXPIRE_TIME,
        issuer: environmentConfig.JWT_ISSUER,
        audience: String(user._id)
      }
    );
    const generatedRefreshToken = await token.generateToken(
      {
        userId: user._id
      },
      environmentConfig.REFRESH_TOKEN_SECRET_KEY,
      {
        expiresIn: environmentConfig.REFRESH_TOKEN_KEY_EXPIRE_TIME,
        issuer: environmentConfig.JWT_ISSUER,
        audience: String(user._id)
      }
    );

    // Save the updated token
    token.refreshToken = generatedRefreshToken;
    token.accessToken = generatedAccessToken;
    token = await token.save();

    // check user is verified or not
    if (!user.isVerified || user.status !== 'active') {
      const verifyEmailLink = `${environmentConfig.WEBSITE_URL}/verify-email?id=${user._id}&token=${token.refreshToken}`;

      // Again send verification email
      const { data: resendEmailData, error } = await sendMail({
        to: user.email,
        ...sendEmailVerificationTemplate(verifyEmailLink, user.firstName)
      });

      // ignore email errors for now
      if (error) {
        if (environmentConfig?.NODE_ENV && environmentConfig.NODE_ENV === 'development') {
          console.log('Sending Email error:', error);
          console.log('Sending Email error:');
        }
      } else if (environmentConfig?.NODE_ENV && environmentConfig.NODE_ENV === 'development') {
        console.log(`Successfully  send email to ${email}...`);
        console.log(resendEmailData);
      }

      const responseData = {
        accessToken: token.accessToken,
        refreshToken: token.refreshToken,
        verifyEmailLink
      };

      return res.status(401).json(
        customResponse<typeof responseData>({
          data: responseData,
          success: false,
          error: true,
          message: `Your Email has not been verified. An Email with Verification link has been sent to your account ${user.email} Please Verify Your Email first or use the email verification lik which is been send with the response to verfiy your email`,
          status: 401
        })
      );
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: pass, confirmPassword, isVerified, isDeleted, status, acceptTerms, ...otherUserInfo } = user._doc;

    const data = {
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
      authToken: token.accessToken
      // user: otherUserInfo
    };

    // Set cookies
    res.cookie('accessToken', token.accessToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // one days
      secure: process.env.NODE_ENV === 'production'
    });

    res.cookie('refreshToken', token.refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      secure: process.env.NODE_ENV === 'production'
    });

    // Set refreshToken' AND accessToken IN cookies
    return res.status(200).json(
      customResponse<typeof data>({
        success: true,
        error: false,
        message: 'Auth logged in successful.',
        status: 200,
        data
      })
    );
  } catch (error) {
    return next(error);
  }
};

export const logoutService: RequestHandler = async (req, res, next) => {
  const { refreshToken } = req.body;

  try {
    const token = await Token.findOne({
      refreshToken
    });

    if (!token) {
      return next(new createHttpError.BadRequest());
    }

    const userId = await verifyRefreshToken(refreshToken);

    if (!userId) {
      return next(new createHttpError.BadRequest());
    }

    // Clear Token
    await Token.deleteOne({
      refreshToken
    });

    // Clear cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    return res.status(200).json(
      customResponse({
        data: null,
        success: true,
        error: false,
        message: 'Successfully logged out 😏 🍀',
        status: 200
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};

export const refreshTokenService: RequestHandler = async (req, res, next) => {
  const { refreshToken } = req.body;

  try {
    let token = await Token.findOne({
      refreshToken
    });

    console.log('token', refreshToken);
    if (!token) {
      return next(new createHttpError.BadRequest());
    }

    const userId = await verifyRefreshToken(refreshToken);

    if (!userId) {
      return next(new createHttpError.BadRequest());
    }

    const generatedAccessToken = await token.generateToken(
      {
        userId
      },
      environmentConfig.ACCESS_TOKEN_SECRET_KEY,
      {
        expiresIn: environmentConfig.ACCESS_TOKEN_KEY_EXPIRE_TIME,
        issuer: environmentConfig.JWT_ISSUER,
        audience: String(userId)
      }
    );
    const generatedRefreshToken = await token.generateToken(
      {
        userId
      },
      environmentConfig.REFRESH_TOKEN_SECRET_KEY,
      {
        expiresIn: environmentConfig.REFRESH_TOKEN_KEY_EXPIRE_TIME,
        issuer: environmentConfig.JWT_ISSUER,
        audience: String(userId)
      }
    );

    // Save the updated token
    token.refreshToken = generatedRefreshToken;
    token.accessToken = generatedAccessToken;
    token = await token.save();

    // Response data
    const data = {
      user: {
        accessToken: token.accessToken,
        refreshToken: token.refreshToken
      }
    };

    // Set cookies
    res.cookie('accessToken', token.accessToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // one days
      secure: process.env.NODE_ENV === 'production'
    });

    res.cookie('refreshToken', token.refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      secure: process.env.NODE_ENV === 'production'
    });

    // Set refreshToken' AND accessToken IN cookies
    return res.status(200).json(
      customResponse<typeof data>({
        data,
        success: true,
        error: false,
        message: 'Auth logged in successful.',
        status: 200
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};

export const updateAccountService = async (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) => {
  const { firstName, lastName, dateOfBirth, email, bio, skills, profileUrl, acceptTerms, phoneNumber, gender } =
    req.body;

  try {
    const user = await User.findById(req.params.userId);

    if (!user) {
      return next(new createHttpError.BadRequest());
    }

    if (!req.user?._id.equals(user._id)) {
      return next(createHttpError(403, `Auth Failed (Unauthorized)`));
    }

    // Check for duplicate email
    if (email) {
      const existingUser = await User.findOne({ email: new RegExp(`^${email}$`, 'i') });
      if (existingUser && !existingUser._id.equals(user._id)) {
        // Remove uploaded file if exists
        if (req.file?.filename) {
          const localFilePath = `${process.env.PWD}/public/uploads/users/${req.file.filename}`;
          deleteFile(localFilePath);
        }
        return next(createHttpError(422, `E-Mail address ${email} is already exists, please pick a different one.`));
      }
    }

    // Handle uploaded profile image
    if (req.file?.filename) {
      const localFilePath = `${process.env.PWD}/public/uploads/users/${req.file.filename}`;

      // Upload to Cloudinary
      const cloudinaryResult = await cloudinary.uploader.upload(localFilePath, {
        folder: 'users',
        overwrite: true,
        resource_type: 'image'
      });

      // Delete local file
      deleteFile(localFilePath);

      // Override profileUrl with Cloudinary URL
      user.profileUrl = cloudinaryResult.secure_url;
    } else if (profileUrl) {
      // Use profileUrl from frontend if provided
      user.profileUrl = profileUrl;
    }

    // Update other fields
    user.firstName = firstName || user.firstName;
    user.lastName = lastName || user.lastName;
    user.email = email || user.email;
    user.gender = gender || user.gender;
    user.dateOfBirth = dateOfBirth || user.dateOfBirth;
    user.phoneNumber = phoneNumber || user.phoneNumber;
    user.acceptTerms = acceptTerms || user.acceptTerms;
    user.bio = bio || user.bio;
    user.skills = skills || user.skills;

    // Save user
    // @ts-ignore
    const updatedUser = await user.save({ validateBeforeSave: false, new: true });

    if (!updatedUser) {
      return next(createHttpError(422, `Failed to update user by given ID ${req.params.userId}`));
    }

    const {
      password: pass,
      confirmPassword,
      isVerified,
      isDeleted,
      status,
      acceptTerms: acceptTerm,
      role,
      ...otherUserInfo
    } = updatedUser._doc;

    return res.status(200).send(
      customResponse<{ user: IUser }>({
        success: true,
        error: false,
        message: `Successfully updated user by ID: ${req.params.userId}`,
        status: 200,
        data: { user: otherUserInfo }
      })
    );
  } catch (error) {
    console.log(error);
    return next(InternalServerError);
  }
};

export const deleteAccountService = async (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) => {
  try {
    const user = await User.findById(req.params.userId);

    if (!user) {
      return next(new createHttpError.BadRequest());
    }

    const reqUser = req.user;

    // Admin cant update them roles
    if (reqUser && reqUser._id.equals(user._id) && reqUser.role === AUTHORIZATION_ROLES.ADMIN) {
      return next(
        createHttpError(403, `Auth Failed (Admin can't remove themselves from admin, please ask another admin)`)
      );
    }

    // User can remove only their own profile
    if (reqUser && !reqUser?._id.equals(user._id) && reqUser?.role !== AUTHORIZATION_ROLES.ADMIN) {
      return next(createHttpError(403, `Auth Failed (Unauthorized)`));
    }

    // Delete user from db
    const deletedUser = await User.findByIdAndDelete({
      _id: req.params.userId
    });

    if (!deletedUser) {
      return next(createHttpError(422, `Failed to delete user by given ID ${req.params.userId}`));
    }

    return res.status(200).json(
      customResponse({
        data: null,
        success: true,
        error: false,
        message: `Successfully deleted user by ID ${req.params.userId}`,
        status: 200
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};

export const getProfileService = async (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) => {
  try {
    const user = await User.findById(req.user?._id)
      .select('-password -confirmPassword  -status -isDeleted -acceptTerms -isVerified')
      .populate('following', 'firstName  lastName  profileUrl bio')
      .populate('followers', 'firstName  lastName  profileUrl bio')
      .populate('blocked', 'firstName  lastName  profileUrl bio')
      .exec();

    if (!user) {
      return next(createHttpError(401, `Auth Failed `));
    }

    const {
      password: pass,
      confirmPassword,
      isVerified,
      isDeleted,
      status,
      acceptTerms,
      // role,
      ...otherUserInfo
    } = user._doc;

    return res.status(200).send(
      customResponse<{ user: IUser }>({
        success: true,
        error: false,
        message: 'Successfully found user profile 🍀',
        status: 200,
        data: { user: otherUserInfo }
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};

export const verifyEmailService = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user)
      return next(
        createHttpError(
          400,
          'Email verification token is invalid or has expired. Please click on resend for verify your Email.'
        )
      );

    // user is already verified
    if (user.isVerified && user.status === 'active') {
      return res.status(200).send(
        customResponse({
          data: null,
          success: true,
          error: false,
          message: `Your email has already been verified. Please Login..`,
          status: 200
        })
      );
    }

    const emailVerificationToken = await Token.findOne({
      userId: user._id,
      refreshToken: req.params.token
    });

    if (!emailVerificationToken) {
      return next(createHttpError(400, 'Email verification token is invalid or has expired.'));
    }
    // Verfiy the user
    user.isVerified = true;
    user.status = 'active';
    user.acceptTerms = true;
    await user.save();

    // Delete the token
    await Token.deleteOne({ _id: emailVerificationToken._id });

    return res.status(200).json(
      customResponse({
        data: null,
        success: true,
        error: false,
        message: 'Your account has been successfully verified . Please Login. ',
        status: 200
      })
    );
  } catch (error) {
    console.log(error);
    return next(InternalServerError);
  }
};

export const forgotPasswordService: RequestHandler = async (req, res, next) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      const message = `The email address ${email} is not associated with any account. Double-check your email address and try again.`;
      return next(createHttpError(401, message));
    }

    let token = await Token.findOne({ userId: user._id });

    if (!token) {
      token = await new Token({ userId: user._id });
      token = await token.save();
    }

    const generatedAccessToken = await token.generateToken(
      {
        userId: user._id
      },
      environmentConfig.ACCESS_TOKEN_SECRET_KEY,
      {
        expiresIn: environmentConfig.ACCESS_TOKEN_KEY_EXPIRE_TIME,
        issuer: environmentConfig.JWT_ISSUER,
        audience: String(user._id)
      }
    );
    const generatedRefreshToken = await token.generateToken(
      {
        userId: user._id
      },
      environmentConfig.REFRESH_TOKEN_SECRET_KEY,
      {
        expiresIn: environmentConfig.REST_PASSWORD_LINK_EXPIRE_TIME,
        issuer: environmentConfig.JWT_ISSUER,
        audience: String(user._id)
      }
    );

    // Save the updated token
    token.refreshToken = generatedRefreshToken;
    token.accessToken = generatedAccessToken;
    token = await token.save();

    const passwordResetEmailLink = `${environmentConfig.WEBSITE_URL}/reset-password?id=${user._id}&token=${token.refreshToken}`;

    // password Reset Email
    const { data: resendEmailData, error } = await sendMail({
      to: user.email,
      ...sendResetPasswordEmailTemplate(passwordResetEmailLink, user.firstName)
    });

    // ignore email errors for now
    if (error) {
      if (process?.env?.NODE_ENV && process.env.NODE_ENV === 'development') {
        console.log('Sending Email error:', error);
        console.log('Sending Email error:');
      }
    } else if (process?.env?.NODE_ENV && process.env.NODE_ENV === 'development') {
      console.log(`Successfully  send email to ${email}...`);
      console.log(resendEmailData);
    }

    const data = {
      user: {
        resetPasswordToken: passwordResetEmailLink
      }
    };

    return res.status(200).json(
      customResponse<typeof data>({
        data,
        success: true,
        error: false,
        message: `Auth success. An Email with Rest password link has been sent to your account ${email}  please check to rest your password or use the the link which is been send with the response body to rest your password`,
        status: 200
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};

export const resetPasswordService: RequestHandler = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return next(createHttpError(401, `Password reset token is invalid or has expired.`));

    const token = await Token.findOne({ userId: req.params.userId, refreshToken: req.params.token });

    if (!token) return next(createHttpError(401, 'Password reset token is invalid or has expired.'));

    const userId = await verifyRefreshToken(req.params.token);

    if (!userId) {
      return next(new createHttpError.BadRequest());
    }

    user.password = req.body.password;
    user.confirmPassword = req.body.confirmPassword;
    await user.save();
    await Token.deleteOne({ userId: req.params.userId, refreshToken: req.params.token });
    // Clear cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    const confirmResetPasswordEmailLink = `${environmentConfig.WEBSITE_URL}/login`;

    const { data: resendEmailData, error } = await sendMail({
      to: user.email,
      ...sendConfirmResetPasswordEmailTemplate(confirmResetPasswordEmailLink, user.firstName)
    });

    // ignore email errors for now
    if (error) {
      if (process?.env?.NODE_ENV && process.env.NODE_ENV === 'development') {
        console.log('Sending Email error:', error);
        console.log('Sending Email error:');
      }
    } else if (process?.env?.NODE_ENV && process.env.NODE_ENV === 'development') {
      console.log(`Successfully  send email to ${user.email}...`);
      console.log(resendEmailData);
    }

    const data = {
      loginLink: confirmResetPasswordEmailLink
    };

    return res.status(200).json(
      customResponse<typeof data>({
        success: true,
        error: false,
        message: `Your password has been Password Reset Successfully updated please login`,
        status: 200,
        data
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};
