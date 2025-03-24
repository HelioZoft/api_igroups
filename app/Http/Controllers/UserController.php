<?php

namespace App\Http\Controllers;

use App\Models\User;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class UserController extends Controller
{
    public function register(Request $request){
        $validator=Validator::make($request->all(),[
            'name'=>'required|string|max:25',
            'email'=>'required|email|unique:users,email',
            'password'=>'required|string|max:12|min:5',

        ]);

        if($validator->fails()){
            return response()->json(['errors'=>$validator->errors()],422);
        }
        $user=User::create([
            'name'=>$request->name,
            'email'=>$request->email,
            'password'=>Hash::make($request->password),
        ]);

        $token=JWTAuth::fromUser($user);
       
        return response()->json([
            'user'=>$user,
            'token'=>$token,
            
        ],201);
    }


    public function login(Request $request){
        $request->validate([
            'email'=>'required|email|max:20',
            'password'=>'required|max:12|min:5',
        ]);

        $user=User::where('email',$request->email)->first();
       
        if(!$user){
            return response()->json([
                'error'=>'Invalid Email',
               
                
            ],401);

        }
        elseif(!Hash::check($request->password,$user->password)){
            return response()->json(['error'=>'Incorrect Password'],401);
        }
       

        $token=JWTAuth::fromUser($user);
       
        return response()->json([
            'message'=>'Login Success',
            'user'=>$user,
            'token'=>$token,
            
        ],201);
    }

    public function dashboard(Request $request){
        
        try{
            $user=JWTAuth::parseToken()->authenticate();
        }catch(\Tymon\JWTAuth\Exceptions\TokenInvalidException $e){
            return response()->json(['error'=>'Token Invalid '],401);

        }
        catch(\Tymon\JWTAuth\Exceptions\TokenExpiredException $e){
            return response()->json(['error'=>'Token expired '],401);

        }

      
        // $user=User::where('email',$request->email)->first();
       
       
        return response()->json([
            'message'=>'welcome to Admin Dashboard',
            'user'=>$user,
            
            
        ],201);
    }
}
