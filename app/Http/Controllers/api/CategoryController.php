<?php

namespace App\Http\Controllers\api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Category;

class CategoryController extends Controller
{
    public function index(){
        $categories = Category::all();
        return response()->json($categories);
    }

    public function store(Request $request){
        $validatedData = $request->validate([
            'nama' =>'required|string|min:3|max:255',
        ]);

        $category = Category::create($validatedData);
        return response()->json($category, 201);
    }

    public function show($id){
        $category = Category::find($id);
        
        if (!$category) {
            return response()->json([
                'status' => 'Category not found'
            ], 404);
        }

        return response()->json($category);
    }

}
