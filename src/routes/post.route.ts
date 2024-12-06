import express from 'express';

import { addPostValidation, isLogin, postIdValidation, postPaginationMiddleware, uploadImage } from '@src/middlewares';
import {
  createPostController,
  deletePostController,
  deleteUserPostsController,
  getPostController,
  getPostsController,
  getTimelinePostsController,
  getUserPostsController
} from '@src/controllers';

const router = express.Router();

router.get('/', postPaginationMiddleware(), getPostsController);
router.get('/user-posts', isLogin, getUserPostsController);
router.get('/timeline', isLogin, getTimelinePostsController);
router.delete('/user-posts', isLogin, deleteUserPostsController);
// router.put('/posts/comment', isAuth, addCommentValidation, addCommentInPostController);
// router.patch('/posts/comment', isAuth, updateCommentValidation, updateCommentInPostController);
// router.delete('/posts/comment', isAuth, deleteCommentValidation, deleteCommentInPostController);
// router.delete('/posts/comment/:postId', isAuth, updatePostValidation, deleteAllCommentInPostController);
// router.delete('/posts/user-comment/:postId', isAuth, postIdValidation, deleteUserCommentInPostController);
// router.get(
//   '/posts/comment/:postId/:commentId',
//   isAuth,
//   postIdValidation,
//   commentIdValidation,
//   getCommentInPostController
// );
// router.get('/posts/comment/:postId', isAuth, postIdValidation, getAllCommentInPostController);
// router.get('/posts/user-comment/:postId', isAuth, updatePostValidation, getUserCommentInPostController);
router.get('/:postId', postIdValidation, getPostController);
router.delete('/:postId', isLogin, postIdValidation, deletePostController);
// router.patch('/posts/:postId', uploadImage.single('postImage'), isAuth, updatePostValidation, updatePostController);
router.post('/', uploadImage.single('postImage'), isLogin, addPostValidation, createPostController);
// router.put('/posts/:postId/like', isAuth, postIdValidation, likePostController);

export = router;
