import { NextFunction, Request, Response } from 'express';

import {
  AddCommentT,
  AuthenticatedRequestBody,
  IPost,
  IUser,
  TPaginationResponse,
  UpdateCommentT
} from '@src/interfaces';
import {
  addCommentInPostService,
  createPostService,
  deletePostService,
  deleteUserPostsService,
  getCommentInPostService,
  getPostService,
  getPostsService,
  getTimelinePostsService,
  getUserPostsService,
  likePostService,
  updateCommentInPostService,
  updatePostService
} from '@src/services';

export const createPostController = (req: AuthenticatedRequestBody<IPost>, res: Response, next: NextFunction) =>
  createPostService(req, res, next);

export const getPostsController = (req: Request, res: TPaginationResponse) => getPostsService(req, res);

export const getPostController = (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) =>
  getPostService(req, res, next);

export const getTimelinePostsController = (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) =>
  getTimelinePostsService(req, res, next);

export const deletePostController = (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) =>
  deletePostService(req, res, next);

export const getUserPostsController = (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) =>
  getUserPostsService(req, res, next);

export const deleteUserPostsController = (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) =>
  deleteUserPostsService(req, res, next);

export const updatePostController = (req: AuthenticatedRequestBody<IPost>, res: Response, next: NextFunction) =>
  updatePostService(req, res, next);

export const likePostController = (req: AuthenticatedRequestBody<IPost>, res: Response, next: NextFunction) =>
  likePostService(req, res, next);

export const addCommentInPostController = (
  req: AuthenticatedRequestBody<AddCommentT>,
  res: Response,
  next: NextFunction
) => addCommentInPostService(req, res, next);

export const updateCommentInPostController = (
  req: AuthenticatedRequestBody<UpdateCommentT>,
  res: Response,
  next: NextFunction
) => updateCommentInPostService(req, res, next);

export const getCommentInPostController = (req: AuthenticatedRequestBody<IUser>, res: Response, next: NextFunction) =>
  getCommentInPostService(req, res, next);
