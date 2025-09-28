import { signUp, signIn, signOut } from '#controllers/auth.controller.js'
import express from 'express'

const authRouter=express.Router()

authRouter.post('/sign-up',signUp)
authRouter.post('/sign-in',signIn)
authRouter.post('/sign-out',signOut)

export default authRouter
