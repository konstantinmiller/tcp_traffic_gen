/****************************************************************************
 * VectorList.h                                                             *
 ****************************************************************************
 * Copyright (C) 2013 Technische Universitaet Berlin                        *
 *                                                                          *
 * Created on: Sep 25, 2013                                                 *
 * Authors: Konstantin Miller <konstantin.miller@tu-berlin.de>              *
 *                                                                          *
 * This program is free software: you can redistribute it and/or modify     *
 * it under the terms of the GNU General Public License as published by     *
 * the Free Software Foundation, either version 3 of the License, or        *
 * (at your option) any later version.                                      *
 *                                                                          *
 * This program is distributed in the hope that it will be useful,          *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of           *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
 * GNU General Public License for more details.                             *
 *                                                                          *
 * You should have received a copy of the GNU General Public License        *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.     *
 ****************************************************************************/

#ifndef VECTORLIST_H_
#define VECTORLIST_H_

#include <vector>
#include <list>

using std::vector;
using std::list;

template <typename T>
class VectorList {
public:
	VectorList(int chunkSize): chunkSize(chunkSize){}
	virtual ~VectorList(){}

	void push_back(const T& t);
    typename list<vector<T> >::const_iterator begin() const {return data.begin();}
	typename list<vector<T> >::const_iterator end() const {return data.end();}

private:
	int chunkSize;
	list<vector<T> > data;
};

template <typename T>
void VectorList<T>::push_back(const T& t)
{
	if(data.empty() || data.back().size() == data.back().capacity())
	{
		data.push_back(vector<T>());
		data.back().reserve(chunkSize);
	}
	data.back().push_back(t);
}

#endif /* VECTORLIST_H_ */
