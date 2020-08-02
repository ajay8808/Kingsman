package com.kingsman.dao;

import java.util.Map;

import com.kingsman.vo.ProductVO;

public interface ProductDao {
//	void create(ProductVO product);

	void read(Map map);
	
	void readOne(Map map); //pserial 조회용

	void readAll(Map map);

	void update(ProductVO product);

//	void delete(String pdserial);
}
