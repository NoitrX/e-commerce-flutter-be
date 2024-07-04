<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    public function register(Request $request) {
        try {
            $request->validate([
               'name' => ['required', 'string', 'max:255'],
               'phone' => ['required', 'string', 'max:255'],
               'username' => ['required', 'string', 'max:255', 'unique:users'],
               'email' => ['required','email', 'string', 'max:255', 'unique:users'],
               'password' => [ 'string', new Password],
            ]);

            User::create([
                'name' => $request->name,
                'phone' => $request->phone,
                'email' => $request->email,
                'username' => $request->username,
                'password' => Hash::make($request->password),
            ]);

            $user = User::where('email', $request->email)->first();
            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Berhasil Di Registrasi');
        }catch(Exception $e) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $e,
            ], 'Auhtentication Failed', 500);
        }
    }

    public function login(Request $request) {
        try {
            $request->validate([
                'email' => 'email|required',
                'password' => 'required'
            ]);

            $credentials = request(['email', 'password']);
            if(!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'mesage' => 'Unauthorized'
                ], 'Authentication Failed', 500);
            }
            $user = User::where('email', $request->email)->first();
            if(!Hash::check($request->password, $user->password, [])) {
                throw new Exception('Invalid Credentials');
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'Login berhasil!');
        }catch(Exception $e) {
            return ResponseFormatter::error([
                'mesage' => 'Something Went Wrong',
                'error' => $e
            ], 'Authentication Failed', 500);
        }
    }
}
