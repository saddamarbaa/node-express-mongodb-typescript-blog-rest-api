import Joi from 'joi';
// @ts-ignore
import JoiObjectId from 'joi-objectid';
import { POST_CATEGORY } from '@src/constants';

const vaildObjectId = JoiObjectId(Joi);

export const postSchema = {
  addPost: Joi.object({
    // Ensure that either filename or photoUrl is provided (not both empty)
    filename: Joi.string().when('photoUrl', {
      is: Joi.string().empty(),
      then: Joi.required().label('Invalid request (Please upload Image)'),
      otherwise: Joi.optional()
    }),
    // photoUrl: Joi.string()
    //   .uri()
    //   .when('filename', {
    //     is: Joi.string().empty(),
    //     then: Joi.required().messages({
    //       'string.uri': 'Please provide a valid URL for the post image'
    //     }),
    //     otherwise: Joi.optional()
    //   }),
    title: Joi.string().min(3).max(100).required(),
    description: Joi.string().min(5).max(5000).required(),
    category: Joi.string().valid(
      POST_CATEGORY.BLOCKCHAIN,
      POST_CATEGORY.CODING,
      POST_CATEGORY.DEVAPP,
      POST_CATEGORY.NEXTJS,
      POST_CATEGORY.NODEJS,
      POST_CATEGORY.REACTJS,
      POST_CATEGORY.SPORTS,
      POST_CATEGORY.TYPESCRIPT,
      POST_CATEGORY.SOCIAL
    )
  }),
  updatePost: Joi.object({
    title: Joi.string().min(3).max(100),
    description: Joi.string().min(5).max(5000),
    postId: vaildObjectId().required(),
    category: Joi.string().valid(
      POST_CATEGORY.BLOCKCHAIN,
      POST_CATEGORY.CODING,
      POST_CATEGORY.DEVAPP,
      POST_CATEGORY.NEXTJS,
      POST_CATEGORY.NODEJS,
      POST_CATEGORY.REACTJS,
      POST_CATEGORY.SPORTS,
      POST_CATEGORY.TYPESCRIPT,
      POST_CATEGORY.SOCIAL
    ),
    filename: Joi.string().label('Invalid request (Please upload Image)')
  }),
  addComment: Joi.object({
    comment: Joi.string().min(3).max(300).required(),
    postId: vaildObjectId().required()
  }),
  updateComment: Joi.object({
    comment: Joi.string().min(3).max(300).required(),
    postId: vaildObjectId().required(),
    commentId: vaildObjectId().required()
  }),
  deleteComment: Joi.object({
    postId: vaildObjectId().required(),
    commentId: vaildObjectId().required()
  }),
  validatedPostId: Joi.object({
    postId: vaildObjectId().required()
  }),
  validatedCommentId: Joi.object({
    commentId: vaildObjectId().required()
  })
};
