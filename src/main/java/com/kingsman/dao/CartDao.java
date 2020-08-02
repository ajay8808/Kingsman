package com.kingsman.dao;

import java.util.Map;

import com.kingsman.vo.CartVO;

public interface CartDao {
	void create(CartVO cart);

//	void read(Map map);

	void readAll(Map map);

//	void update(CartVO cart);

	void delete(int cnum);
}
