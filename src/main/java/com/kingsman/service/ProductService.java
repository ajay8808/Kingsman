package com.kingsman.service;

import java.util.Map;

import com.kingsman.vo.ProductVO;

public interface ProductService {
//	void insertProduct(ProductVO product); //상품등록인데 우리는 import로만.
	void selectProduct(Map map); //member가 보고싶은 상품종류만
	void selectProductOne(Map map); //pserial로 조회할 method
	void selectAllProducts(Map map);  //(member, admin 둘다)모든 상품조회
	void updateProduct(ProductVO product); //(admin) 상품사진, 수량
//	void deleteProduct(String userid); 

}
