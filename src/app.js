import express from 'express';
import logger from '#config/logger.js';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors'
import cookieParser from 'cookie-parser';
import authRouter from '#routes/auth.routes.js';
import securityMiddleware from '#middlewares/security.js';

const app = express();

app.use(helmet())
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(cookieParser())

app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));

app.use(securityMiddleware)


app.get('/', (req, res) => {
    logger.info('Hello from Acquisitions!') 

  res.status(200).send('Hello from Acquisitions');
});

app.get('/api/health', (req, res) => {

  res.status(200).json({status:'ok',timestamp:new Date().toISOString(),uptime:process.uptime()});
});

app.get('/api', (req, res) => {

  res.status(200).json({message:'Acquisition Api is running...'});
});

app.use('/api/auth',authRouter)

export default app;
