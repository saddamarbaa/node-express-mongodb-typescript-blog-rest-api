import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv-safe';
import cookieParser from 'cookie-parser';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';
import colors from 'colors';

import apiV1 from '@src/api/v1';
import * as middlewares from './middlewares/errors';
import homeRoutes from '@src/routes/home.route';

import '@src/middlewares/errors/unhandledRejection';

const swaggerDocument = YAML.load(`${process.cwd()}/swagger/swagger.yaml`);

dotenv.config();
colors.enable();

// Initialize app with express
const app = express();

// Load App Middleware
app.use(morgan('dev'));
// app.use(cors());
// app.use(
//   cors({
//     origin: process.env.CLIENT_URL || 'http://localhost:3000',
//     credentials: true
//   })
// );

app.use(
  cors({
    origin: (origin, callback) => {
      // allow requests with no origin (mobile apps, curl, Postman)
      if (!origin) return callback(null, true);
      callback(null, true); // allow all other origins
    },
    credentials: true
  })
);

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  helmet({
    crossOriginResourcePolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false
  })
);

// Serve all static files inside public directory.
app.use('/static', express.static('public'));

app.use(homeRoutes);
app.use('/api/v1', apiV1);

// Error handling
app.use(middlewares.notFound);
app.use(middlewares.errorHandler);

export default app;
