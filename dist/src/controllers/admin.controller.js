"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.adminClearAllPostsController = exports.adminDeleteCommentInPostController = exports.adminDeleteAllCommentInPostController = exports.adminDeleteAllPostForGivenUserController = exports.adminDeletePostController = exports.adminUpdatePostController = exports.adminCreatePostController = exports.adminGetPostController = exports.adminGetPostsController = exports.adminRemoveUserController = exports.adminUpdateAuthController = exports.adminAddUserController = exports.adminGetUserController = exports.adminGetUsersController = void 0;
const services_1 = require("@src/services");
const adminGetUsersController = (req, res) => (0, services_1.adminGetUsersService)(req, res);
exports.adminGetUsersController = adminGetUsersController;
const adminGetUserController = (req, res, next) => (0, services_1.adminGetUserService)(req, res, next);
exports.adminGetUserController = adminGetUserController;
const adminAddUserController = (req, res, next) => (0, services_1.adminAddUserService)(req, res, next);
exports.adminAddUserController = adminAddUserController;
const adminUpdateAuthController = (req, res, next) => (0, services_1.adminUpdateAuthService)(req, res, next);
exports.adminUpdateAuthController = adminUpdateAuthController;
const adminRemoveUserController = (req, res, next) => (0, services_1.deleteAccountService)(req, res, next);
exports.adminRemoveUserController = adminRemoveUserController;
const adminGetPostsController = (req, res) => (0, services_1.adminGetPostsService)(req, res);
exports.adminGetPostsController = adminGetPostsController;
const adminGetPostController = (req, res, next) => (0, services_1.adminGetPostService)(req, res, next);
exports.adminGetPostController = adminGetPostController;
const adminCreatePostController = (req, res, next) => (0, services_1.adminCreatePostService)(req, res, next);
exports.adminCreatePostController = adminCreatePostController;
const adminUpdatePostController = (req, res, next) => (0, services_1.adminUpdatePostService)(req, res, next);
exports.adminUpdatePostController = adminUpdatePostController;
const adminDeletePostController = (req, res, next) => (0, services_1.adminDeletePostService)(req, res, next);
exports.adminDeletePostController = adminDeletePostController;
const adminDeleteAllPostForGivenUserController = (req, res, next) => (0, services_1.adminDeleteAllPostForGivenUserService)(req, res, next);
exports.adminDeleteAllPostForGivenUserController = adminDeleteAllPostForGivenUserController;
const adminDeleteAllCommentInPostController = (req, res, next) => (0, services_1.adminDeleteAllCommentInPostService)(req, res, next);
exports.adminDeleteAllCommentInPostController = adminDeleteAllCommentInPostController;
const adminDeleteCommentInPostController = (req, res, next) => (0, services_1.adminDeleteCommentInPostService)(req, res, next);
exports.adminDeleteCommentInPostController = adminDeleteCommentInPostController;
const adminClearAllPostsController = (req, res, next) => (0, services_1.adminClearAllPostsService)(req, res, next);
exports.adminClearAllPostsController = adminClearAllPostsController;
//# sourceMappingURL=admin.controller.js.map