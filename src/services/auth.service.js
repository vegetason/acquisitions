import bcrypt from 'bcrypt'
import { db } from '#config/database.js'
import { eq } from 'drizzle-orm'
import { users } from '#models/user.model.js'
import logger from "#config/logger.js"

export const hashPassword=async (password)=>{
    try {
        return await bcrypt.hash(password,10)
    } catch (error) {
        logger.error(`Error hashing the Password: ${error}`)
        throw new Error('Error hashing')
    }
}

export const comparePassword=async (password, hash)=>{
    try {
        return await bcrypt.compare(password, hash)
    } catch (error) {
        logger.error(`Error comparing the Password: ${error}`)
        throw new Error('Error comparing password')
    }
}

export const createUser=async({name,email,password,role='user'})=>{
    try {
        const existingUser= db.select().from(users).where(eq(users.email,email))
        if (existingUser.lenght>0) throw new Error('User already exists.');
        const password_hash=await hashPassword(password)
        const [newUser]= await db.insert(users).values({name,email,password:password_hash,role}).returning({id: users.id,name:users.name,email:users.email,role:users.role,created_at:users.created_at})

        logger.info(`User ${newUser.email} created successfully`)
        return newUser
    } catch (error) {
                logger.error(`Error creating User: ${error}`)
        throw error
    }
}

export const authenticateUser = async ({ email, password }) => {
    try {
        const [user] = await db.select().from(users).where(eq(users.email, email))
        if (!user) {
            throw new Error('Invalid email or password')
        }

        const isValid = await comparePassword(password, user.password)
        if (!isValid) {
            throw new Error('Invalid email or password')
        }

        logger.info(`User authenticated successfully: ${email}`)
        const { password: _password, ...safeUser } = user
        return safeUser
    } catch (error) {
        if (error.message !== 'Invalid email or password') {
            logger.error(`Error authenticating User: ${error}`)
        }
        throw error
    }
}
