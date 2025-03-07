import { NextFunction, Response } from 'express';
import createHttpError, { InternalServerError } from 'http-errors';

import { AuthenticatedRequestBody, IUser } from '@src/interfaces';
import { customResponse } from '@src/utils';
import User from '@src/models/User.model';

export const getUsersService = async (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) => {
  try {
    const users = await User.find({})
      .select('-password -confirmPassword  -status -isDeleted -acceptTerms -isVerified -isDeleted')
      .populate('followers', 'firstName lastName profileUrl bio')
      .populate('following', 'firstName lastName profileUrl bio')
      .populate('blocked', 'firstName lastName profileUrl bio')
      .exec();

    return res.status(200).send(
      customResponse({
        success: true,
        error: false,
        message: `Users retrieved successfully`,
        status: 200,
        data: { users }
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};

export const getUserService = async (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) => {
  try {
    const { userId } = req.params;

    const user = await User.findOne({
      id: userId
    })
      .select('-password -confirmPassword -status -isDeleted -acceptTerms -isVerified')
      .populate('followers', 'firstName lastName profileUrl bio')
      .populate('following', 'firstName lastName profileUrl bio')
      .populate('blocked', 'firstName lastName profileUrl bio')
      .exec();

    if (!user) {
      return next(createHttpError(400, `User not found`));
    }

    return res.status(200).send(
      customResponse({
        success: true,
        error: false,
        message: 'User retrieved successfully',
        status: 200,
        data: { user }
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};

export const followUserService = async (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) => {
  try {
    if (req.user?._id.equals(req.params.userId)) {
      return next(createHttpError(403, `You cannot follow yourself`));
    }

    const toBeFollowedUser = await User.findById(req.params.userId).populate('followers');

    if (!toBeFollowedUser) {
      return next(createHttpError(400, `User not found`));
    }

    const currentUser = await User.findById(req.user?._id).populate('following');

    const isAlreadyFollowed = toBeFollowedUser.followers.some(function (user) {
      if (user._id.toString() === currentUser?._id.toString()) return true;
      return false;
    });

    if (!isAlreadyFollowed) {
      await toBeFollowedUser.updateOne({
        $push: {
          followers: currentUser?._id
        },
        new: true
      });

      await currentUser?.updateOne({
        $push: {
          following: req.params.userId
        }
      });

      const updatedUser = await User?.findById(req.user?._id)
        .select('-password -confirmPassword  -status -isDeleted -acceptTerms -isVerified')
        .populate('following', 'firstName  lastName  profileUrl bio')
        .populate('followers', 'firstName  lastName  profileUrl bio')
        .exec();

      return res.status(200).send(
        customResponse<{ user: IUser }>({
          success: true,
          error: false,
          message: `User has been followed successfully`,
          status: 200,
          data: { user: updatedUser! }
        })
      );
    }

    return next(createHttpError(403, `You already followed this user`));
  } catch (error) {
    console.log(error);
    return next(InternalServerError);
  }
};

export const unFollowUserService = async (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) => {
  try {
    if (req.user?._id.equals(req.params.userId)) {
      return next(createHttpError(403, `You cant un follow yourself`));
    }

    const toBeFollowedUser = await User.findById(req.params.userId);
    if (!toBeFollowedUser) {
      return next(createHttpError(400, `User not found`));
    }

    const currentUser = await User.findById(req.user?._id).populate('following');
    if (!currentUser) {
      return next(createHttpError(400, `Current user not found`));
    }

    const isAlreadyFollowed = toBeFollowedUser.followers.some(function (follower) {
      return follower._id.toString() === currentUser._id.toString();
    });

    if (isAlreadyFollowed) {
      // Update both users: remove followers and following relationship
      await toBeFollowedUser.updateOne({ $pull: { followers: currentUser._id } }, { new: true });
      await currentUser.updateOne({ $pull: { following: req.params.userId } });

      // Fetch the updated user info and populate necessary fields
      const updatedUser = await User.findById(req.user?._id)
        .select('-password -confirmPassword  -status -isDeleted -acceptTerms -isVerified')
        .populate('following', 'firstName  lastName  profileUrl bio')
        .populate('followers', 'firstName  lastName  profileUrl bio')
        .exec();

      // Check if updatedUser is null
      if (!updatedUser) {
        return next(createHttpError(400, `Updated user not found`));
      }

      return res.status(200).send(
        customResponse<{ user: IUser }>({
          success: true,
          error: false,
          message: `User has been unfollowed successfully`,
          status: 200,
          data: { user: updatedUser }
        })
      );
    }

    // If the current user is not following the user to be unfollowed
    return next(createHttpError(403, `You haven't followed this user before`));
  } catch (error) {
    return next(InternalServerError);
  }
};

export const blockUserService = async (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) => {
  try {
    // Ensure the user is not blocking themselves
    if (req.user?._id.equals(req.params.userId)) {
      return next(createHttpError(403, `You cannot block yourself`));
    }

    const toBeBlockedUser = await User.findById(req.params.userId);
    if (!toBeBlockedUser) {
      return next(createHttpError(400, `User not found`));
    }

    const currentUser = await User.findById(req.user?._id)
      .populate('following', 'firstName  lastName  profileUrl bio')
      .populate('followers', 'firstName  lastName  profileUrl bio')
      .populate('blocked', 'firstName  lastName  profileUrl bio')
      .exec();

    if (!currentUser) {
      return next(createHttpError(400, `Current user not found`));
    }

    // Check if the user is already blocked
    const isAlreadyBlocked = currentUser.blocked.some(function (user) {
      if (user._id.toString() === toBeBlockedUser._id.toString()) return true;
      return false;
    });

    if (isAlreadyBlocked) {
      return next(createHttpError(403, `You already blocked this user`));
    }

    // Block the user
    await currentUser.updateOne({
      $push: {
        blocked: req.params.userId
      }
    });

    // Unfollow and remove the blocked user from followers/following list if they exist
    await currentUser.updateOne({
      $pull: { following: req.params.userId, followers: req.params.userId }
    });
    await toBeBlockedUser.updateOne({
      $pull: { following: req.user?._id, followers: req.user?._id }
    });

    return res.status(200).send(
      customResponse<{ user: IUser }>({
        success: true,
        error: false,
        message: `User has been blocked successfully`,
        status: 200,
        data: { user: currentUser }
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};

export const unBlockUserService = async (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) => {
  try {
    // Ensure the user is not trying to unblock themselves
    if (req.user?._id.equals(req.params.userId)) {
      return next(createHttpError(403, `You cannot unblock yourself`));
    }

    const toBeUnblockedUser = await User.findById(req.params.userId);
    if (!toBeUnblockedUser) {
      return next(createHttpError(400, `User not found`));
    }

    const currentUser = await User.findById(req.user?._id)
      .populate('following', 'firstName  lastName  profileUrl bio')
      .populate('followers', 'firstName  lastName  profileUrl bio')
      .populate('blocked', 'firstName  lastName  profileUrl bio')
      .exec();

    if (!currentUser) {
      return next(createHttpError(400, `Current user not found`));
    }

    // Check if the user is currently blocked
    const isBlocked = currentUser.blocked.some(function (blockedUser) {
      return blockedUser._id.toString() === toBeUnblockedUser._id.toString();
    });

    if (isBlocked) {
      // Unblock the user
      await currentUser.updateOne({
        $pull: {
          blocked: req.params.userId
        }
      });

      // Filter out the unblocked user from the blocked array before sending the response
      const updatedBlockedList = currentUser.blocked.filter(
        (blockedUser) => blockedUser._id.toString() !== req.params.userId
      );

      const updatedUserResponse = {
        ...currentUser.toObject(),
        blocked: updatedBlockedList
      };

      return res.status(200).send(
        customResponse<{ user: IUser }>({
          success: true,
          error: false,
          message: `User has been unblocked successfully`,
          status: 200,
          data: { user: updatedUserResponse }
        })
      );
    }

    return next(createHttpError(403, `You have not blocked this user`));
  } catch (error) {
    return next(InternalServerError);
  }
};

export const whoViewedMyProfileService = async (
  req: AuthenticatedRequestBody<IUser>,
  res: Response,
  next: NextFunction
) => {
  try {
    // Check if the user is trying to view their own profile
    if (req.user?._id.equals(req.params.userId)) {
      return next(createHttpError(403, `You cannot view your own profile`));
    }

    // 1. Find the profile being viewed (the original user)
    const toBeViewedUser = await User.findById(req.params.userId);
    if (!toBeViewedUser) {
      return next(createHttpError(404, 'User not found'));
    }

    // 2. Get the authenticated user who is viewing the profile
    const userWhoViewed = req.user as IUser;

    // 3. Check if the user has already viewed the profile
    const isUserAlreadyViewed = toBeViewedUser.viewers.some(
      (viewer) => viewer.toString() === userWhoViewed?._id.toString()
    );

    // 4. If already viewed, return an error
    if (isUserAlreadyViewed) {
      return next(createHttpError(400, 'You have already viewed this profile'));
    }

    // 5. If not viewed yet, add the authenticated user's ID to the viewers array
    toBeViewedUser.viewers.push(userWhoViewed._id);

    // 6. Save the updated user profile
    await toBeViewedUser.save();

    return res.status(200).send(
      customResponse({
        success: true,
        error: false,
        message: 'Profile view recorded successfully',
        status: 200,
        data: null
      })
    );
  } catch (error) {
    return next(InternalServerError);
  }
};
