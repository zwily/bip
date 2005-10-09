/*
 * $Id: conf.h,v 1.5 2005/04/17 15:20:32 nohar Exp $
 *
 * This file is part of the bip project
 * Copyright (C) 2004 2005 Arnaud Cornet and Loïc Gomez
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#ifndef TUPLE_H
#define TUPLE_H

#define TUPLE_STR 0
#define TUPLE_INT 1
#define TUPLE_LIST 2

struct tuple {
	int type;
	void *pdata;
	int ndata;
	int tuple_type;
};
#endif
