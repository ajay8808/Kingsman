package com.kingsman.dao;

import java.util.Map;

import com.kingsman.vo.BoardVO;

public interface BoardDao {
	void create(BoardVO board);

//	void read(Map map);

	void readAll(Map map);

//	void update(BoardVO board);

	void delete(int bnum);
}
