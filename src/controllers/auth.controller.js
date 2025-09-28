import logger from "#config/logger.js"
import { createUser, authenticateUser } from "#services/auth.service.js"
import { cookies } from "#utils/cookies.js"
import { formatValidationError } from "#utils/format.js"
import { jwtToken } from "#utils/jwt.js"
import { signUpSchema, signInSchema } from "#validations/auth.validation.js"

export const signUp=async(req,res,next)=>{
    try {
        const validationResult=signUpSchema.safeParse(req.body)
        if(!validationResult.success) return res.status(400).json({
            error:'validation failed',
            details:formatValidationError(validationResult.error)
        })

        const {name,email,password,role}=validationResult.data

        const user= await createUser({name,email,password,role})

        const token=jwtToken.sign({id:user.id,name:user.name,email:user.email,role:user.email})

        cookies.set(res,'token',token)
        
        
        logger.info(`User registered successfully: ${email} `)
        res.status(201).json({
            message:"User registered",
            user:{
                id:user.id,name:user.name,email:user.email,role:user.role
            }
        })
    } catch (error) {
        logger.error('Sign up error',error)
        if(error.message==='User with this email already exists'){
            return res.status(409).json({error:'Email already exist'})
        }
        next(error)
    }
}

export const signIn=async(req,res,next)=>{
    try {
        const validationResult=signInSchema.safeParse(req.body)
        if(!validationResult.success) return res.status(400).json({
            error:'validation failed',
            details:formatValidationError(validationResult.error)
        })

        const { email, password } = validationResult.data

        const user = await authenticateUser({ email, password })

        const token = jwtToken.sign({ id:user.id, name:user.name, email:user.email, role:user.role })

        cookies.set(res,'token',token)

        logger.info(`User signed in successfully: ${email}`)
        res.status(200).json({
            message:"User signed in",
            user:{
                id:user.id, name:user.name, email:user.email, role:user.role
            }
        })
    } catch (error) {
        logger.error('Sign in error',error)
        if(error.message==='Invalid email or password'){
            return res.status(401).json({error:'Invalid email or password'})
        }
        next(error)
    }
}

export const signOut=async(req,res,next)=>{
    try {
        cookies.clear(res,'token')
        logger.info('User signed out successfully')
        res.status(200).json({ message:'User signed out' })
    } catch (error) {
        logger.error('Sign out error',error)
        next(error)
    }
}
