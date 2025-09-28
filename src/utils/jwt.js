import jwt from "jsonwebtoken"
import "dotenv/config"
import logger from "#config/logger.js"

const JWT_SECRET=process.env.JWT_SECRET||'Your secret key please change in production'
const JWT_EXPIRES_IN='1d'

export const jwtToken={
    sign:(payload)=>{
        try {
            return jwt.sign(payload,JWT_SECRET,{expiresIn:JWT_EXPIRES_IN} )
        } catch (error) {
            logger.error('Failed to authenticate a Token',error)
            throw new Error('Failed to authenticate Token')
        }
    },
    verify:(token)=>{
        try {
            return jwt.verify(token,JWT_SECRET)
        } catch (error) {
            logger.error('Failed to authenticate a Token',error)
            throw new Error('Failed to authenticate Token')
        }
    }
}